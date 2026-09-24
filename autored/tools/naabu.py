"""AutoRed naabu tool wrapper — Phase 1, Task 8.

Reuses ``_save_raw`` from ``autored.tools.nmap`` (Task 7) so every tool
wrapper persists raw artefacts via the same path scheme.
"""
from __future__ import annotations

import json
from typing import Literal

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.subprocess_runner import run_subprocess
from autored.tools.nmap import _save_raw  # reuse from nmap

log = get_logger("tools.naabu")


class NaabuPort(BaseModel):
    port: int
    protocol: Literal["tcp", "udp"]
    host: str


class PortList(BaseModel):
    target: str
    ports: list[NaabuPort] = Field(default_factory=list)
    raw_output_path: str = ""
    command: str = ""
    duration_sec: float = 0.0


def _build_naabu_cmd(target: str, ports: str) -> list[str]:
    """Build a naabu argv list. Output goes to stdout as JSONL."""
    return ["naabu", "-host", target, "-port", ports, "-json", "-silent"]


def _parse_naabu_jsonl(text: str) -> list[NaabuPort]:
    """Parse naabu JSONL stdout into a list of NaabuPort.

    Skips blank/malformed lines (logged at warning) so a single bad line
    doesn't lose the whole sweep.
    """
    ports: list[NaabuPort] = []
    for line in text.strip().splitlines():
        if not line:
            continue
        try:
            data = json.loads(line)
            ports.append(
                NaabuPort(
                    port=data["port"],
                    protocol=data.get("proto", "tcp"),
                    host=data.get("ip", ""),
                )
            )
        except (json.JSONDecodeError, KeyError) as e:
            log.warning("naabu_parse_line_failed", line=line, error=str(e))
            continue
    return ports


@tool
@roe_guard(allowed_categories=["recon", "read_only"])
async def naabu_scan(
    target: str,
    ports: str = "top-1000",
    engagement_id: str = "",
) -> PortList:
    """Run naabu for fast port sweep.

    Args:
        target: IP, CIDR, or hostname
        ports: Port spec (e.g., "top-1000", "1-65535", "80,443,8080")
        engagement_id: Current engagement ID

    Returns:
        PortList with discovered ports
    """
    cmd = _build_naabu_cmd(target, ports)
    log.info("naabu_start", target=target, ports=ports)

    result = await run_subprocess(cmd, timeout=300)
    raw_path = await _save_raw(
        "naabu", target, result.stdout, result.stderr, engagement_id
    )

    ports_found = _parse_naabu_jsonl(result.stdout)
    log.info(
        "naabu_done",
        target=target,
        ports_found=len(ports_found),
        duration=result.duration_sec,
    )

    return PortList(
        target=target,
        ports=ports_found,
        raw_output_path=raw_path,
        command=result.command,
        duration_sec=result.duration_sec,
    )
