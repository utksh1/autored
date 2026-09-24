"""AutoRed dnsx tool wrapper — Phase 1, Task 14.

Runs dnsx for DNS record resolution (A, AAAA, CNAME, MX, TXT) with JSON
output and parses findings into a ``DnsOutput`` Pydantic model.

Reuses ``_save_raw`` from ``autored.tools.nmap`` (Task 7) so every tool
wrapper persists raw artefacts via the same path scheme.

Decorator order note (Ruling 1 in the SDD ledger): ``@tool`` is applied
OUTERMOST and ``@roe_guard`` INNER. The brief spec'd the opposite order
(``@roe_guard`` over ``@tool``), but that produces a StructuredTool that
is not callable via ``.ainvoke({...})`` at runtime — see Batch A review.
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

log = get_logger("tools.dnsx")


class DnsRecord(BaseModel):
    hostname: str
    record_type: Literal["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]
    value: str
    ttl: int = 0


class DnsResult(BaseModel):
    hostname: str
    records: list[DnsRecord] = Field(default_factory=list)


class DnsOutput(BaseModel):
    results: list[DnsResult] = Field(default_factory=list)
    raw_output_path: str = ""
    command: str = ""
    duration_sec: float = 0.0


def _build_dnsx_cmd(hostnames: list[str]) -> list[str]:
    """Build a dnsx argv list. Output goes to stdout as JSONL via ``-json``.

    dnsx accepts ``-d`` for a single host or ``-l`` for a file. For small
    lists we pass each hostname as a separate ``-d`` flag — avoids the
    round-trip of writing a temp list file.
    """
    cmd: list[str] = [
        "dnsx",
        "-a",
        "-aaaa",
        "-cname",
        "-mx",
        "-txt",
        "-json",
        "-silent",
    ]
    for h in hostnames:
        cmd.extend(["-d", h])
    return cmd


def _parse_dnsx_jsonl(text: str) -> list[DnsResult]:
    """Parse dnsx JSONL stdout into a list of DnsResult (one per host).

    The fixture file is ``dnsx_lame.json`` (``.json`` extension) but the
    content is JSONL — one JSON object per line — matching what the real
    dnsx binary emits with ``-json``.

    dnsx emits one JSON object per (host, query) — a single host may have
    multiple JSONL lines if multiple record types were resolved. We merge
    by host into a single ``DnsResult`` and append one ``DnsRecord`` per
    (record_type, value) pair.

    Skips blank/malformed lines silently (dnsx emits a lot of noise).
    """
    results_by_host: dict[str, DnsResult] = {}
    for line in text.strip().splitlines():
        if not line:
            continue
        try:
            data = json.loads(line)
            host = data.get("host", "")
            if not host:
                continue
            if host not in results_by_host:
                results_by_host[host] = DnsResult(hostname=host)

            # Each record type that's present
            for rt in ["a", "aaaa", "cname", "mx", "txt", "ns", "soa"]:
                values = data.get(rt, [])
                if isinstance(values, str):
                    values = [values]
                for v in values:
                    results_by_host[host].records.append(
                        DnsRecord(
                            hostname=host,
                            record_type=rt.upper(),  # type: ignore[arg-type]
                            value=v,
                            ttl=data.get("ttl", 0),
                        )
                    )
        except (json.JSONDecodeError, KeyError) as e:
            log.warning("dnsx_parse_line_failed", line=line, error=str(e))

    return list(results_by_host.values())


@tool
@roe_guard(allowed_categories=["recon", "read_only"])
async def dns_resolve(
    hostnames: list[str],
    engagement_id: str = "",
) -> DnsOutput:
    """Resolve DNS records for hostnames.

    Args:
        hostnames: List of hostnames to resolve
        engagement_id: Current engagement ID

    Returns:
        DnsOutput with list of DnsResult, one per hostname
    """
    if not hostnames:
        return DnsOutput()

    cmd = _build_dnsx_cmd(hostnames)
    log.info("dnsx_start", hostnames=hostnames)

    result = await run_subprocess(cmd, timeout=60)
    raw_path = await _save_raw(
        "dnsx", ",".join(hostnames), result.stdout, result.stderr, engagement_id
    )

    results = _parse_dnsx_jsonl(result.stdout)
    log.info(
        "dnsx_done",
        hostnames=len(hostnames),
        resolved=len(results),
        duration=result.duration_sec,
    )

    return DnsOutput(
        results=results,
        raw_output_path=raw_path,
        command=result.command,
        duration_sec=result.duration_sec,
    )
