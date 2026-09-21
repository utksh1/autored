from langchain_core.tools import tool

from autored.logging import get_logger
from autored.tools.metasploit import metasploit_rpc, MsfResult

log = get_logger("subagents.msfagent")


@tool
async def msfagent_subagent(
    module: str,
    target: str,
    payload: str,
    lhost: str,
    lport: int,
    options: dict | None = None,
    engagement_id: str = "",
) -> MsfResult:
    """Execute a Metasploit exploit module via RPC.

    Args:
        module: Full module path (e.g., "exploit/windows/smb/ms17_010_eternalblue")
        target: Target RHOSTS
        payload: Payload module
        lhost: Local host for reverse connection
        lport: Local port for reverse connection
        options: Additional module options
        engagement_id: Current engagement ID

    Returns:
        MsfResult with job/session info.
    """
    log.info("msfagent_start", module=module, target=target)
    result = await metasploit_rpc.ainvoke({
        "method": "execute_exploit",
        "params": {
            "module": module, "target": target, "payload": payload,
            "lhost": lhost, "lport": lport, "options": options,
        },
        "engagement_id": engagement_id,
    })
    log.info("msfagent_done", module=module, success=result.success)
    return result
