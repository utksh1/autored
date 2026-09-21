import shlex
from pydantic import BaseModel, Field
from langchain_core.tools import tool
from autored.roe_guard import roe_guard
from autored.subprocess_runner import run_subprocess
from autored.tools.nmap import _save_raw
from autored.logging import get_logger

log = get_logger("tools.custom")


class CustomResult(BaseModel):
    command: str
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    success: bool = False
    raw_output_path: str = ""
    duration_sec: float = 0.0


@tool
@roe_guard(allowed_categories=["exploit"])
async def custom_command(
    command: str,
    engagement_id: str = "",
) -> CustomResult:
    """Execute an arbitrary approved command.

    This is the escape hatch for exploits that don't fit sqlmap/hydra/metasploit.
    The command must have been approved at a HitL gate before this tool is called.

    Args:
        command: Full command to execute (already approved by operator)
        engagement_id: Current engagement ID

    Returns:
        CustomResult with command output.
    """
    cmd_list = shlex.split(command)
    log.info("custom_command_start", command=command)

    result = await run_subprocess(cmd_list, timeout=600)
    raw_path = await _save_raw("custom", command, result.stdout, result.stderr, engagement_id)

    log.info("custom_command_done", command=command, returncode=result.returncode)
    return CustomResult(
        command=command,
        stdout=result.stdout,
        stderr=result.stderr,
        returncode=result.returncode,
        success=result.returncode == 0,
        raw_output_path=raw_path,
        duration_sec=result.duration_sec,
    )
