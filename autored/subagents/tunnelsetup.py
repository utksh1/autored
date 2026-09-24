"""TunnelSetup sub-agent (spec §7.4, Phase 5).

Sets up a pivot tunnel when ``PivotRecord.needs_tunnel`` is True.
Default: a chisel reverse SOCKS tunnel back to the AutoRed host
(``AUTORED_LHOST``), because the pivot target may sit on a subnet the
AutoRed host can't route to. Thin wrapper — the chisel tool already
records the TunnelConfig **including its teardown command**.

A tunnel failure returns ``tunnel=None`` — it must never kill the
pivot itself (the pivot already succeeded; the tunnel is optional
reachability).
"""
from langchain_core.tools import tool
from pydantic import BaseModel

from autored.logging import get_logger
from autored.models.lateral import TunnelConfig
from autored.tools.tunnel import chisel_reverse

log = get_logger("subagents.tunnelsetup")


class TunnelSetupOutput(BaseModel):
    """Result of a tunnel bring-up attempt."""

    tunnel: TunnelConfig | None = None


@tool
async def tunnelsetup_subagent(
    pivot: dict,
    engagement_id: str = "",
) -> TunnelSetupOutput:
    """Set up a tunnel for a completed pivot.

    Args:
        pivot: A PivotRecord.model_dump() dict (needs_tunnel=True).
        engagement_id: Current engagement ID.

    Returns:
        TunnelSetupOutput with the TunnelConfig, or tunnel=None when
        the bring-up failed (non-fatal — the pivot stands).
    """
    target = pivot.get("target_host", "unknown")
    log.info("tunnelsetup_start", target=target)
    try:
        result = await chisel_reverse.ainvoke(
            lhost="",  # default → AUTORED_LHOST inside the tool
            lport=1080,
            target_network="0.0.0.0/0",
            engagement_id=engagement_id,
        )
        log.info("tunnelsetup_done", target=target,
                 teardown=result.tunnel_config.teardown_command)
        return TunnelSetupOutput(tunnel=result.tunnel_config)
    except Exception as exc:  # noqa: BLE001 — tunnel is best-effort
        log.warning("tunnelsetup_failed", target=target, error=str(exc))
        return TunnelSetupOutput(tunnel=None)
