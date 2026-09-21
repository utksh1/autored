from typing import Literal

from langchain_core.tools import tool
from pydantic import BaseModel

from autored.logging import get_logger
from autored.tools.naabu import naabu_scan, PortList
from autored.tools.nmap import nmap_scan, NmapResult

log = get_logger("subagents.portscan")


class PortScanInput(BaseModel):
    target: str
    scan_type: Literal["quick", "full", "service"] = "quick"
    engagement_id: str = ""


class PortScanOutput(BaseModel):
    target: str
    fast_scan: PortList | None = None
    deep_scan: NmapResult | None = None


@tool
async def portscan_subagent(
    target: str,
    scan_type: str = "quick",
    engagement_id: str = "",
) -> PortScanOutput:
    """Run port scan: naabu for fast sweep, then nmap for deep service scan on open ports.

    Args:
        target: IP, CIDR, or hostname
        scan_type: "quick" (top 100), "full" (all ports), "service" (service detection)
        engagement_id: Current engagement ID

    Returns:
        PortScanOutput with fast_scan (naabu) and deep_scan (nmap) results.
        If no open ports found, deep_scan is None.
    """
    log.info("portscan_start", target=target, scan_type=scan_type)

    # Step 1: Fast port sweep with naabu
    fast_scan = await naabu_scan.ainvoke({
        "target": target,
        "ports": "top-1000",
        "engagement_id": engagement_id,
    })

    # Step 2: Determine open ports
    open_ports = [p.port for p in fast_scan.ports]
    if not open_ports:
        log.info("portscan_no_open_ports", target=target)
        return PortScanOutput(target=target, fast_scan=fast_scan)

    # Step 3: Deep scan with nmap on open ports (cap at 100 to keep manageable)
    ports_str = ",".join(str(p) for p in open_ports[:100])
    nmap_scan_type = "service" if scan_type == "service" else "quick"
    deep_scan = await nmap_scan.ainvoke({
        "target": target,
        "scan_type": nmap_scan_type,
        "ports": ports_str,
        "engagement_id": engagement_id,
    })

    log.info("portscan_done", target=target, open_ports=len(open_ports))
    return PortScanOutput(target=target, fast_scan=fast_scan, deep_scan=deep_scan)
