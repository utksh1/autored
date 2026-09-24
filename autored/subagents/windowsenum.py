"""WindowsEnum sub-agent.

Thin wrapper around the :func:`winpeas_run` tool (Phase 4 Task 3). The
Post-Ex Agent (Phase 4 Task 11) dispatches one WindowsEnum per Windows
foothold; the sub-agent runs winpeas and surfaces the parsed
:class:`WinpeasResult` on :class:`WindowsEnumOutput`.
"""
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.models.postex import PrivescCandidate, Secret, User
from autored.tools.winpeas import WinpeasResult, winpeas_run

log = get_logger("subagents.windowsenum")


class WindowsEnumOutput(BaseModel):
    host_ip: str
    winpeas_result: WinpeasResult | None = None
    users: list[User] = Field(default_factory=list)
    secrets: list[Secret] = Field(default_factory=list)
    privesc_candidates: list[PrivescCandidate] = Field(default_factory=list)


@tool
async def windowsenum_subagent(
    foothold_id: str,
    host_ip: str,
    engagement_id: str = "",
) -> WindowsEnumOutput:
    """Run Windows enumeration (winpeas) on a foothold.

    Args:
        foothold_id: ID of the foothold to enumerate.
        host_ip: IP of the foothold host.
        engagement_id: Current engagement ID.

    Returns:
        WindowsEnumOutput with the parsed winpeas result. Phase 5 will
        populate the users / secrets / privesc_candidates lists from
        the winpeas sections via an LLM post-processing pass.
    """
    log.info("windowsenum_start", host_ip=host_ip, foothold_id=foothold_id)
    result = await winpeas_run.ainvoke({
        "foothold_id": foothold_id,
        "host_ip": host_ip,
        "engagement_id": engagement_id,
    })
    log.info(
        "windowsenum_done",
        host_ip=host_ip,
        autologon=len(result.autologon_credentials),
        modifiable_services=len(result.modifiable_services),
        unattended=len(result.unattended_files),
    )
    return WindowsEnumOutput(host_ip=host_ip, winpeas_result=result)
