"""LinuxEnum sub-agent.

Thin wrapper around the :func:`linpeas_run` tool (Phase 4 Task 3). The
Post-Ex Agent (Phase 4 Task 11) dispatches one LinuxEnum per Linux
foothold; the sub-agent runs linpeas and surfaces the parsed
:class:`LinpeasResult` on :class:`LinuxEnumOutput`.

The wrapper exists to provide a stable sub-agent boundary the Post-Ex
Agent can reason about — analogous to how Phase 2's CVEMatcher /
ExploitFinder / HypothesisCritic wrap their underlying tools. Phase 5
will extend the Post-Ex Agent's LLM planner to additionally derive
:class:`User`, :class:`Secret`, and :class:`PrivescCandidate` records
from the linpeas output; for Phase 4 the sub-agent simply carries the
parsed linpeas result.
"""
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.models.postex import PrivescCandidate, Secret, User
from autored.tools.linpeas import LinpeasResult, linpeas_run

log = get_logger("subagents.linuxenum")


class LinuxEnumOutput(BaseModel):
    host_ip: str
    linpeas_result: LinpeasResult | None = None
    users: list[User] = Field(default_factory=list)
    secrets: list[Secret] = Field(default_factory=list)
    privesc_candidates: list[PrivescCandidate] = Field(default_factory=list)


@tool
async def linuxenum_subagent(
    foothold_id: str,
    host_ip: str,
    engagement_id: str = "",
) -> LinuxEnumOutput:
    """Run Linux enumeration (linpeas) on a foothold.

    Args:
        foothold_id: ID of the foothold to enumerate.
        host_ip: IP of the foothold host.
        engagement_id: Current engagement ID.

    Returns:
        LinuxEnumOutput with the parsed linpeas result. Phase 5 will
        populate the users / secrets / privesc_candidates lists from
        the linpeas sections via an LLM post-processing pass.
    """
    log.info("linuxenum_start", host_ip=host_ip, foothold_id=foothold_id)
    result = await linpeas_run.ainvoke({
        "foothold_id": foothold_id,
        "host_ip": host_ip,
        "engagement_id": engagement_id,
    })
    log.info(
        "linuxenum_done",
        host_ip=host_ip,
        cves=len(result.cves),
        suid=len(result.suid_binaries),
        cron=len(result.cron_jobs),
    )
    return LinuxEnumOutput(host_ip=host_ip, linpeas_result=result)
