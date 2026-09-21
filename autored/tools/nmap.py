import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Literal

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.subprocess_runner import run_subprocess

log = get_logger("tools.nmap")

ScanType = Literal["quick", "full", "udp", "vuln", "service"]


class NmapPort(BaseModel):
    port: int
    protocol: Literal["tcp", "udp"]
    state: Literal["open", "closed", "filtered", "open|filtered"]
    service: str | None = None
    version: str | None = None
    product: str | None = None


class NmapHost(BaseModel):
    ip: str
    hostname: str | None = None
    mac: str | None = None
    os_guess: str | None = None
    ports: list[NmapPort] = Field(default_factory=list)


class NmapResult(BaseModel):
    target: str
    scan_type: ScanType
    started_at: datetime = Field(default_factory=datetime.utcnow)
    duration_sec: float = 0.0
    hosts: list[NmapHost] = Field(default_factory=list)
    raw_output_path: str = ""
    command: str = ""


NMAP_FLAGS = {
    "quick":   ["-T4", "-F", "--top-ports", "100"],
    "full":    ["-T4", "-p-", "--min-rate", "5000"],
    "udp":     ["-sU", "--top-ports", "50", "-T4"],
    "vuln":    ["-T4", "-A", "--script", "vuln", "-p-"],
    "service": ["-T4", "-sV", "-sC", "-p-"],
}


def _build_nmap_cmd(target: str, scan_type: str, ports: str | None) -> list[str]:
    flags = NMAP_FLAGS.get(scan_type, NMAP_FLAGS["quick"])
    cmd = ["nmap", "-oX", "-", "--stats-every", "10s"]
    cmd.extend(flags)
    if ports:
        cmd.extend(["-p", ports])
    cmd.append(target)
    return cmd


async def _save_raw(tool: str, target: str, stdout: str, stderr: str, engagement_id: str) -> str:
    raw_dir = Path(f"engagements/{engagement_id}/raw")
    raw_dir.mkdir(parents=True, exist_ok=True)
    nonce = datetime.utcnow().strftime("%H%M%S_%f")[:10]
    out_path = raw_dir / f"{tool}_{nonce}.out"
    err_path = raw_dir / f"{tool}_{nonce}.err"
    out_path.write_text(stdout)
    err_path.write_text(stderr)
    return str(out_path)


def _parse_nmap_xml(xml_str: str) -> list[NmapHost]:
    root = ET.fromstring(xml_str)
    hosts = []
    for host_elem in root.findall("host"):
        addr_elem = host_elem.find("address")
        if addr_elem is None:
            continue
        ip = addr_elem.get("addr")

        # Find MAC address (second address element with addrtype="mac")
        mac = None
        for addr in host_elem.findall("address"):
            if addr.get("addrtype") == "mac":
                mac = addr.get("addr")
                break

        hostnames = [h.get("name") for h in host_elem.findall("./hostnames/hostname")]
        hostname = hostnames[0] if hostnames else None

        # OS guess
        os_elem = host_elem.find("./os/osmatch")
        os_guess = os_elem.get("name") if os_elem is not None else None

        ports = []
        for port_elem in host_elem.findall("./ports/port"):
            port_num = int(port_elem.get("portid"))
            protocol = port_elem.get("protocol")
            state_elem = port_elem.find("state")
            state = state_elem.get("state") if state_elem is not None else "unknown"
            service_elem = port_elem.find("service")
            service = service_elem.get("name") if service_elem is not None else None
            product = service_elem.get("product") if service_elem is not None else None
            version = service_elem.get("version") if service_elem is not None else None
            # Coerce state to literal — nmap can return other values, but we accept the 4 main ones
            if state not in ("open", "closed", "filtered", "open|filtered"):
                state = "filtered"  # safe default
            ports.append(NmapPort(
                port=port_num, protocol=protocol, state=state,
                service=service, product=product, version=version,
            ))
        hosts.append(NmapHost(ip=ip, hostname=hostname, mac=mac, os_guess=os_guess, ports=ports))
    return hosts


@tool
@roe_guard(allowed_categories=["recon", "read_only"])
async def nmap_scan(
    target: str,
    scan_type: ScanType = "quick",
    ports: str | None = None,
    engagement_id: str = "",
) -> NmapResult:
    """Run nmap against target. Returns parsed services and ports.

    Args:
        target: IP, CIDR, or hostname to scan
        scan_type: One of: quick (top 100), full (all ports), udp, vuln, service
        ports: Optional port range string (e.g., "1-1000" or "80,443,8080")
        engagement_id: Current engagement ID for raw output storage

    Returns:
        NmapResult with parsed hosts, ports, services
    """
    cmd = _build_nmap_cmd(target, scan_type, ports)
    log.info("nmap_start", target=target, scan_type=scan_type, cmd=cmd)

    result = await run_subprocess(cmd, timeout=600)
    raw_path = await _save_raw("nmap", target, result.stdout, result.stderr, engagement_id)

    if result.returncode != 0:
        log.error("nmap_failed", target=target, returncode=result.returncode,
                  stderr=result.stderr[:500])
        # Still try to parse what we got — nmap sometimes returns non-zero with valid XML

    try:
        hosts = _parse_nmap_xml(result.stdout)
    except ET.ParseError as e:
        log.error("nmap_parse_failed", target=target, error=str(e),
                  raw_path=raw_path)
        hosts = []  # empty result, but raw is saved

    log.info("nmap_done", target=target, hosts_found=len(hosts), duration=result.duration_sec)

    return NmapResult(
        target=target,
        scan_type=scan_type,
        started_at=datetime.utcnow(),
        duration_sec=result.duration_sec,
        hosts=hosts,
        raw_output_path=raw_path,
        command=result.command,
    )
