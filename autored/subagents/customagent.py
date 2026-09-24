from langchain_core.tools import tool

from autored.logging import get_logger
from autored.tools.custom import custom_command, CustomResult

log = get_logger("subagents.customagent")


@tool
async def customagent_subagent(
    command: str,
    engagement_id: str = "",
) -> CustomResult:
    """Execute an arbitrary approved command.

    Args:
        command: Full command to execute (already approved by operator)
        engagement_id: Current engagement ID

    Returns:
        CustomResult with command output.
    """
    log.info("customagent_start", command=command)
    result = await custom_command.ainvoke({
        "command": command,
        "engagement_id": engagement_id,
    })
    log.info("customagent_done", command=command, success=result.success)
    return result
