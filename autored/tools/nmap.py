"""AutoRed nmap tool wrapper — Phase 1, Task 7.

Pattern setter for the rest of the Phase 1 tool wrappers. Defines the
``_save_raw`` helper imported by every later tool (naabu, httpx, ...).

The wrapper:
- Builds an nmap command via ``_build_nmap_cmd`` (no shell, no interpolation).
- Runs it through the shared ``run_subprocess`` (with timeout + RoE guard).
- Parses the XML stdout via ``_parse_nmap_xml``.
- Persists the raw stdout/stderr to ``engagements/<id>/raw/``.
- Returns a Pydantic ``NmapResult`` (never a raw string).

Spec ref: §6.5 (recon layer), §6.8 (RoE guard), §3.3 (raw artefacts on disk).
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Literal

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.persistence.filesystem import ENGAGEMENTS_DIR
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
    # Literal[] here mirrors the function signature, so the result model
    # refuses a hallucinated scan_type. (Review-focus test in Step 7.)
    scan_type: ScanType
    started_at: datetime = Field(default_factory=datetime.utcnow)
    duration_sec: float = 0.0
    hosts: list[NmapHost] = Field(default_factory=list)
    raw_output_path: str = ""
    command: str = ""


NMAP_FLAGS: dict[str, list[str]] = {
    "quick": ["-T4", "-F", "--top-ports", "100"],
    "full": ["-T4", "-p-", "--min-rate", "5000"],
    "udp": ["-sU", "--top-ports", "50", "-T4"],
    "vuln": ["-T4", "-A", "--script", "vuln", "-p-"],
    "service": ["-T4", "-sV", "-sC", "-p-"],
}


def _build_nmap_cmd(target: str, scan_type: str, ports: str | None) -> list[str]:
    """Build an nmap argv list. Falls back to "quick" flags for unknown types.

    Never returns a shell string — the caller passes this directly to
    ``asyncio.create_subprocess_exec``.
    """
    flags = NMAP_FLAGS.get(scan_type, NMAP_FLAGS["quick"])
    cmd: list[str] = ["nmap", "-oX", "-", "--stats-every", "10s"]
    cmd.extend(flags)
    if ports:
        cmd.extend(["-p", ports])
    cmd.append(target)
    return cmd


async def _save_raw(
    tool: str,
    target: str,
    stdout: str,
    stderr: str,
    engagement_id: str,
) -> str:
    """Persist raw stdout/stderr to engagements/<id>/raw/<tool>_<nonce>.{out,err}.

    Returns the .out path so the calling wrapper can record it in its result
    model. Imported by every later tool wrapper (naabu, httpx, ...).
    """
    raw_dir = ENGAGEMENTS_DIR / engagement_id / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    nonce = datetime.utcnow().strftime("%H%M%S_%f")[:10]
    out_path = raw_dir / f"{tool}_{nonce}.out"
    err_path = raw_dir / f"{tool}_{nonce}.err"
    out_path.write_text(stdout)
    err_path.write_text(stderr)
    return str(out_path)


def _parse_nmap_xml(xml_str: str) -> list[NmapHost]:
    """Parse nmap XML stdout into a list of NmapHost.

    Raises ``xml.etree.ElementTree.ParseError`` on malformed XML — the
    calling wrapper catches it and returns an empty hosts list with the
    raw artefact still saved.
    """
    root = ET.fromstring(xml_str)
    hosts: list[NmapHost] = []
    for host_elem in root.findall("host"):
        addr_elem = host_elem.find("address")
        if addr_elem is None:
            continue
        ip = addr_elem.get("addr")

        # Find MAC address (second address element with addrtype="mac")
        mac: str | None = None
        for addr in host_elem.findall("address"):
            if addr.get("addrtype") == "mac":
                mac = addr.get("addr")
                break

        hostnames = [h.get("name") for h in host_elem.findall("./hostnames/hostname")]
        hostname = hostnames[0] if hostnames else None

        # OS guess
        os_elem = host_elem.find("./os/osmatch")
        os_guess = os_elem.get("name") if os_elem is not None else None

        ports: list[NmapPort] = []
        for port_elem in host_elem.findall("./ports/port"):
            port_num = int(port_elem.get("portid"))
            protocol_str = port_elem.get("protocol")
            # Coerce to Literal["tcp","udp"] — default tcp if nmap emits something weird
            if protocol_str == "udp":
                protocol: Literal["tcp", "udp"] = "udp"
            else:
                protocol = "tcp"
            state_elem = port_elem.find("state")
            state = state_elem.get("state") if state_elem is not None else "unknown"
            service_elem = port_elem.find("service")
            service = service_elem.get("name") if service_elem is not None else None
            product = service_elem.get("product") if service_elem is not None else None
            version = service_elem.get("version") if service_elem is not None else None
            # Coerce state to literal — nmap can return other values, but we
            # accept the 4 main ones; anything else collapses to "filtered".
            if state not in ("open", "closed", "filtered", "open|filtered"):
                state = "filtered"  # safe default
            ports.append(
                NmapPort(
                    port=port_num,
                    protocol=protocol,
                    state=state,  # type: ignore[arg-type]
                    service=service,
                    product=product,
                    version=version,
                )
            )
        hosts.append(
            NmapHost(
                ip=ip or "",
                hostname=hostname,
                mac=mac,
                os_guess=os_guess,
                ports=ports,
            )
        )
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
    raw_path = await _save_raw(
        "nmap", target, result.stdout, result.stderr, engagement_id
    )

    if result.returncode != 0:
        log.error(
            "nmap_failed",
            target=target,
            returncode=result.returncode,
            stderr=result.stderr[:500],
        )
        # Still try to parse what we got — nmap sometimes returns non-zero with
        # valid XML.

    try:
        hosts = _parse_nmap_xml(result.stdout)
    except ET.ParseError as e:
        log.error(
            "nmap_parse_failed",
            target=target,
            error=str(e),
            raw_path=raw_path,
        )
        hosts = []  # empty result, but raw is saved

    log.info(
        "nmap_done",
        target=target,
        hosts_found=len(hosts),
        duration=result.duration_sec,
    )

    return NmapResult(
        target=target,
        scan_type=scan_type,  # type: ignore[arg-type]
        started_at=datetime.utcnow(),
        duration_sec=result.duration_sec,
        hosts=hosts,
        raw_output_path=raw_path,
        command=result.command,
    )
