"""AutoRed Metasploit RPC tool wrapper — Phase 3, Task 5.

This is the only non-subprocess tool in Phase 3: it talks to the Metasploit
RPC daemon (``msfrpcd``) over HTTP using MessagePack-encoded bodies. The
daemon is started out-of-band by the operator::

    msfrpcd -P msf -p 55553 -a 127.0.0.1

and the tool's ``MsfRpcClient`` authenticates via ``auth.login``, then
dispatches subsequent calls (``module.execute``, ``session.list``,
``session.info``) with the cached token.

Decorator order note (Ruling 1 in the SDD ledger): ``@tool`` is applied
OUTERMOST and ``@roe_guard`` INNER. The opposite order produces a
StructuredTool that is not callable via ``.ainvoke({...})`` at runtime —
see Batch A review.

Wire-format note: the brief's Step 1 test asserted on the literal bytes
``b"\\x92\\xa3tmp_token"`` as the ``auth.login`` response, but those bytes
are not valid msgpack for ``["tmp_token"]`` (``\\xa3`` is fixstr-len-3 and
``\\x92`` is fixarray-len-2, leaving 6 unconsumed bytes). The real msfrpcd
``auth.login`` response is ``["success", "<token>"]``, which is what we
mock in ``tests/unit/tools/test_metasploit.py`` and what the brief's
``token[1]`` extraction logic was clearly designed to consume.
"""
from __future__ import annotations

import time
from typing import Any

import httpx
import msgpack
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.roe_guard import roe_guard

log = get_logger("tools.metasploit")


class MsfResult(BaseModel):
    """Result envelope for every ``metasploit_rpc`` call.

    ``success`` + ``error`` are mutually exclusive: a True success means
    ``data`` is populated with the parsed RPC response; a False success
    means ``error`` carries the human-readable reason. ``method`` echoes
    the dispatched method name so callers can correlate.
    """

    method: str
    success: bool = False
    data: dict = Field(default_factory=dict)
    error: str | None = None
    duration_sec: float = 0.0


class MsfRpcClient:
    """Async client for the Metasploit RPC daemon (``msfrpcd``).

    Requires ``msfrpcd`` running on the specified ``host:port``. Start
    with::

        msfrpcd -P <password> -p 55553 -a 127.0.0.1

    The client caches the auth token on ``login()`` and includes it in
    every subsequent ``_call()`` payload (per msfrpcd's token-in-list
    convention).

    I4-partial fix (Phase 4 fix wave): previously ``_call()`` raised
    ``RuntimeError("Not authenticated. Call login() first.")`` when
    invoked pre-auth on any method other than ``auth.login`` — which
    forced every caller (including the ``metasploit_rpc`` tool) to
    remember the login gate. The class now auto-logins inside
    ``_call()`` if no token is cached AND the method isn't
    ``auth.login``; the cached token is reused on subsequent calls.
    The token is only set on a successful login (``login()`` raises
    on failure, so we never cache ``None``).
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 55553,
        password: str = "msf",
    ) -> None:
        self.host = host
        self.port = port
        self.password = password
        self.token: str | None = None
        self.url = f"http://{host}:{port}/api/"

    async def _call(self, method: str, *args: Any) -> Any:
        """Make a single RPC call to ``msfrpcd``.

        Packs ``[method, token, *args]`` when authenticated, or
        ``[method, *args]`` for the auth.login bootstrap call.

        I4-partial fix: if no token is cached AND the method isn't
        ``auth.login``, auto-login first instead of raising
        ``RuntimeError``. The cached token is then reused on
        subsequent calls (and across calls when the
        ``metasploit_rpc`` tool shares a client via
        ``_get_cached_client``).
        """
        if not self.token and method != "auth.login":
            # Auto-login gate — replaces the previous RuntimeError
            # raise. ``login()`` only caches ``self.token`` on
            # success, so a failed login still raises and we never
            # cache ``None``.
            await self.login()

        # msfrpcd expects the token in the message pack list when authenticated.
        payload: list[Any] = (
            [method, self.token, *args] if self.token else [method, *args]
        )
        msgpack_data = msgpack.packb(payload)

        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.post(self.url, content=msgpack_data)
            if response.status_code != 200:
                raise RuntimeError(f"MSF RPC returned {response.status_code}")
            result = msgpack.unpackb(response.content, raw=False)
            if isinstance(result, dict) and "error" in result:
                raise RuntimeError(f"MSF RPC error: {result['error']}")
            return result

    async def login(self) -> str:
        """Authenticate to ``msfrpcd``. Returns the cached session token.

        msfrpcd's ``auth.login`` returns ``["success", "<token>"]`` on a
        good password. The brief's extraction logic handles both the
        2-element list form and the bare-string fallback (older msfrpcd
        builds). Wraps any underlying exception (transport error, non-200
        status, RPC error key) in a ``RuntimeError`` mentioning the host
        so callers see a single error type on every failure mode.
        """
        try:
            token = await self._call("auth.login", self.password)
            if isinstance(token, list) and len(token) >= 2:
                self.token = token[1]
            elif isinstance(token, str):
                self.token = token
            else:
                self.token = str(token)
            log.info("msf_login_success", host=self.host)
            return self.token
        except Exception as e:
            log.error("msf_login_failed", host=self.host, error=str(e))
            raise RuntimeError(f"MSF RPC login failed: {e}") from e

    async def execute_exploit(
        self,
        module: str,
        target: str,
        payload: str,
        lhost: str,
        lport: int,
        options: dict | None = None,
    ) -> dict:
        """Execute a Metasploit exploit module.

        Args:
            module: Full module path (e.g.,
                ``exploit/windows/smb/ms17_010_eternalblue``).
            target: Target RHOSTS (IP or CIDR).
            payload: Payload module (e.g.,
                ``windows/x64/meterpreter/reverse_tcp``).
            lhost: Local host for the reverse connection.
            lport: Local port for the reverse connection.
            options: Additional module options merged on top of the
                defaults below (e.g., ``{"SESSION": 1}``).

        Returns:
            The raw unpacked RPC response, coerced to ``dict`` when the
            msfrpcd response was a map; anything else is wrapped under
            ``{"raw": result}`` so the Pydantic ``MsfResult.data: dict``
            field accepts it.
        """
        opts = {
            "RHOSTS": target,
            "PAYLOAD": payload,
            "LHOST": lhost,
            "LPORT": str(lport),
        }
        if options:
            opts.update(options)

        # msfrpcd's module.execute wants the module's leaf name (the part
        # after the final "/"), not the full dotted path.
        result = await self._call(
            "module.execute", "exploit", module.split("/")[-1], opts
        )
        log.info(
            "msf_exploit_executed", module=module, target=target, result=result
        )
        return result if isinstance(result, dict) else {"raw": result}

    async def list_sessions(self) -> dict:
        """List active Meterpreter sessions."""
        return await self._call("session.list")

    async def check_session(self, session_id: int) -> dict:
        """Get info about a specific session."""
        return await self._call("session.info", session_id)


# I4-partial fix: module-level client cache so the ``metasploit_rpc``
# tool doesn't re-authenticate on every call. Keyed by
# ``(host, port, password)`` so distinct msfrpcd instances get distinct
# clients. The cached client retains its auth token across tool
# invocations — ``_call()``'s auto-login gate fires exactly once per
# (host, port, password) triple, and subsequent calls ride the cached
# token. ``_reset_client_cache`` is a test-isolation hook.
_CLIENT_CACHE: dict[tuple[str, int, str], MsfRpcClient] = {}


def _get_cached_client(
    host: str, port: int, password: str
) -> MsfRpcClient:
    """Return a cached ``MsfRpcClient`` for the given connection triple.

    Creates a new client on first call and caches it; subsequent calls
    return the same instance so the auth token survives across
    ``metasploit_rpc`` tool invocations. Distinct msfrpcd instances
    (different host / port / password) get distinct cached clients.
    """
    key = (host, port, password)
    if key not in _CLIENT_CACHE:
        _CLIENT_CACHE[key] = MsfRpcClient(
            host=host, port=port, password=password
        )
    return _CLIENT_CACHE[key]


def _reset_client_cache() -> None:
    """Clear the module-level client cache. Test-isolation hook."""
    _CLIENT_CACHE.clear()


@tool
@roe_guard(allowed_categories=["exploit"])
async def metasploit_rpc(
    method: str,
    params: dict,
    engagement_id: str = "",
) -> MsfResult:
    """Execute a Metasploit RPC method against a running ``msfrpcd``.

    The RoE guard at decoration time checks that ``exploit`` is allowed
    for ``engagement_id`` before the RPC is dispatched; on block, the
    guard raises ``RoEViolation`` rather than returning an ``MsfResult``
    with ``success=False`` (block ≠ soft failure).

    Args:
        method: RPC method. Dispatched here: ``"login"``,
            ``"execute_exploit"``, ``"list_sessions"``. Anything else
            falls through to the error branch (the brief's dispatch
            table does not include ``"check_session"`` even though the
            client class supports it; the LLM orchestrator should call
            ``list_sessions`` first, then ``check_session`` via a future
            extension).
        params: Method parameters. ``host`` / ``port`` / ``password``
            configure the underlying ``MsfRpcClient``; the rest are
            forwarded to the dispatched method (e.g., ``module``,
            ``target``, ``payload``, ``lhost``, ``lport`` for
            ``execute_exploit``).
        engagement_id: Current engagement ID (used by the RoE guard).

    Returns:
        ``MsfResult`` with ``success=True`` + ``data`` populated on a
        clean RPC call, or ``success=False`` + ``error`` populated on
        any exception (transport error, non-200 status, unknown method).
    """
    start = time.time()

    # I4-partial fix: use the module-level cached client so the auth
    # token survives across ``metasploit_rpc`` invocations. The first
    # call to ``_call()`` (or to ``login()``) per
    # ``(host, port, password)`` triple populates the cached token;
    # subsequent calls reuse it. The redundant ``if not client.token:
    # await client.login()`` guards below remain as belt-and-suspenders
    # (harmless when the token is already cached).
    client = _get_cached_client(
        host=params.get("host", "127.0.0.1"),
        port=params.get("port", 55553),
        password=params.get("password", "msf"),
    )

    try:
        if method == "login":
            token = await client.login()
            return MsfResult(
                method=method,
                success=True,
                data={"token": token},
                duration_sec=time.time() - start,
            )
        elif method == "execute_exploit":
            if not client.token:
                await client.login()
            result = await client.execute_exploit(
                module=params["module"],
                target=params["target"],
                payload=params["payload"],
                lhost=params["lhost"],
                lport=params["lport"],
                options=params.get("options"),
            )
            return MsfResult(
                method=method,
                success=True,
                data=result,
                duration_sec=time.time() - start,
            )
        elif method == "list_sessions":
            if not client.token:
                await client.login()
            sessions = await client.list_sessions()
            return MsfResult(
                method=method,
                success=True,
                data={"sessions": sessions},
                duration_sec=time.time() - start,
            )
        else:
            return MsfResult(
                method=method,
                success=False,
                error=f"Unknown method: {method}",
                duration_sec=time.time() - start,
            )
    except Exception as e:
        log.error("msf_rpc_failed", method=method, error=str(e))
        return MsfResult(
            method=method,
            success=False,
            error=str(e),
            duration_sec=time.time() - start,
        )
