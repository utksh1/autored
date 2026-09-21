"""EvasionAgent sub-agent.

Wraps the three evasion tools added in Phase 4 Task 7 that are
applicable to a Windows foothold:

* :func:`amsi_bypass`      — patch AMSI in-memory so script content
  isn't reported.
* :func:`log_clear`        — clear Security / System / Application
  event logs.
* :func:`defender_disable` — flip off Defender realtime + behaviour
  monitoring.

(ETW patch and process injection are added in a later phase — the
Post-Ex Agent's LLM planner will selectively enable them based on the
foothold's defensive posture.)

Each tool returns an :class:`EvasionResult` with the PowerShell
command string; the sub-agent converts each into an
:class:`EvasionAction` record (with a stable id and timestamp) so the
Phase 5 Cleanup Agent can audit which evasions were applied and (where
reversible) undo them.

The sub-agent is a thin wrapper — actual execution is delegated to
the Phase 6 foothold session manager.
"""
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.models.postex import EvasionAction
from autored.tools.evasion import (
    amsi_bypass,
    defender_disable,
    log_clear,
)

log = get_logger("subagents.evasionagent")


class EvasionAgentOutput(BaseModel):
    host_ip: str
    actions: list[EvasionAction] = Field(default_factory=list)


@tool
async def evasionagent_subagent(
    host_ip: str,
    engagement_id: str = "",
) -> EvasionAgentOutput:
    """Run defense-evasion actions against a Windows foothold.

    Executes AMSI bypass, event-log clear, and Defender disable in
    sequence and records each as an :class:`EvasionAction`.

    Args:
        host_ip: Target host IP.
        engagement_id: Current engagement ID.

    Returns:
        EvasionAgentOutput with one EvasionAction per evasion
        technique invoked.
    """
    log.info("evasionagent_start", host_ip=host_ip)

    actions: list[EvasionAction] = []

    # AMSI bypass — patch in-memory so the subsequent PowerShell
    # commands aren't scanned by Windows Defender.
    amsi = await amsi_bypass.ainvoke({
        "host_ip": host_ip,
        "engagement_id": engagement_id,
    })
    actions.append(EvasionAction(
        host_ip=host_ip,
        technique="amsi_bypass",
        target="AMSI",
        success=amsi.success,
        command=amsi.command,
    ))

    # Clear event logs — wipe the Security / System / Application
    # logs so the prior post-ex activity (mimikatz, persistence
    # install, etc.) doesn't leave forensic traces.
    log_res = await log_clear.ainvoke({
        "host_ip": host_ip,
        "engagement_id": engagement_id,
    })
    actions.append(EvasionAction(
        host_ip=host_ip,
        technique="log_clear",
        target="Security/System/Application logs",
        success=log_res.success,
        command=log_res.command,
    ))

    # Disable Defender — flip off realtime + behaviour monitoring so
    # subsequent post-ex tooling (persistence, exfil) isn't blocked.
    defender = await defender_disable.ainvoke({
        "host_ip": host_ip,
        "engagement_id": engagement_id,
    })
    actions.append(EvasionAction(
        host_ip=host_ip,
        technique="defender_disable",
        target="Windows Defender",
        success=defender.success,
        command=defender.command,
    ))

    log.info(
        "evasionagent_done",
        host_ip=host_ip,
        actions=len(actions),
        successes=sum(1 for a in actions if a.success),
    )
    return EvasionAgentOutput(host_ip=host_ip, actions=actions)
