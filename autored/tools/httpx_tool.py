"""AutoRed httpx tool wrapper — Phase 1, Task 9.

File is named ``httpx_tool.py`` (not ``httpx.py``) to avoid shadowing the
real ``httpx`` Python package on the import path. The exposed tool function
is still ``httpx_probe`` (so the RoE categoriser in ``roe_guard`` finds it
under its canonical name).

Reuses ``_save_raw`` from ``autored.tools.nmap`` (Task 7).
"""
from __future__ import annotations

import json

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.subprocess_runner import run_subprocess
from autored.tools.nmap import _save_raw  # reuse from nmap

log = get_logger("tools.httpx")


class HttpxResult(BaseModel):
    url: str
    status_code: int
    title: str | None = None
    tech_stack: list[str] = Field(default_factory=list)
    content_length: int = 0
    web_server: str | None = None
    redirects: bool = False
    final_url: str | None = None


class HttpxOutput(BaseModel):
    results: list[HttpxResult] = Field(default_factory=list)
    raw_output_path: str = ""
    command: str = ""
    duration_sec: float = 0.0


def _build_httpx_cmd(hosts: list[str], ports: list[int]) -> list[str]:
    """Build httpx argv list. Uses one ``-u`` flag per host for small lists."""
    cmd: list[str] = [
        "httpx",
        "-tech-detect",
        "-status-code",
        "-title",
        "-json",
        "-silent",
    ]
    for host in hosts:
        cmd.extend(["-u", host])
    if ports:
        cmd.extend(["-ports", ",".join(str(p) for p in ports)])
    return cmd


def _parse_httpx_json(text: str) -> list[HttpxResult]:
    """Parse httpx JSONL stdout into a list of HttpxResult.

    The fixture file is ``httpx_lame.json`` (``.json`` extension) but the
    content is JSONL — one JSON object per line — so we parse line-by-line
    rather than ``json.loads(text)``. This matches what the real httpx
    binary emits with ``-json``.
    """
    results: list[HttpxResult] = []
    for line in text.strip().splitlines():
        if not line:
            continue
        try:
            data = json.loads(line)
            results.append(
                HttpxResult(
                    url=data.get("url", ""),
                    status_code=data.get("status_code", 0),
                    title=data.get("title") or None,
                    tech_stack=data.get("tech", []) or [],
                    content_length=data.get("content_length", 0),
                    web_server=data.get("web_server") or None,
                    redirects=bool(data.get("redirect")),
                    final_url=data.get("final_url"),
                )
            )
        except json.JSONDecodeError as e:
            log.warning("httpx_parse_line_failed", line=line, error=str(e))
    return results


@tool
@roe_guard(allowed_categories=["recon", "read_only"])
async def httpx_probe(
    hosts: list[str],
    ports: list[int] | None = None,
    engagement_id: str = "",
) -> HttpxOutput:
    """Probe hosts for HTTP services with tech detection.

    Args:
        hosts: List of URLs or IPs to probe
        ports: Optional list of ports to probe (e.g., [80, 443, 8080])
        engagement_id: Current engagement ID

    Returns:
        HttpxOutput with list of HttpxResult, one per responding host
    """
    if not hosts:
        return HttpxOutput()

    cmd = _build_httpx_cmd(hosts, ports or [80, 443, 8080, 8443])
    log.info("httpx_start", hosts=hosts, ports=ports)

    result = await run_subprocess(cmd, timeout=120)
    raw_path = await _save_raw(
        "httpx", ",".join(hosts), result.stdout, result.stderr, engagement_id
    )

    results = _parse_httpx_json(result.stdout)
    log.info(
        "httpx_done",
        hosts_probed=len(hosts),
        results=len(results),
        duration=result.duration_sec,
    )

    return HttpxOutput(
        results=results,
        raw_output_path=raw_path,
        command=result.command,
        duration_sec=result.duration_sec,
    )
