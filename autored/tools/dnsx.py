import json
from pathlib import Path
from typing import Literal
from pydantic import BaseModel, Field
from langchain_core.tools import tool
from autored.roe_guard import roe_guard
from autored.subprocess_runner import run_subprocess
from autored.tools.nmap import _save_raw
from autored.logging import get_logger

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
    cmd = ["dnsx", "-a", "-aaaa", "-cname", "-mx", "-txt", "-json", "-silent"]
    # dnsx accepts -d for single or -l for file; for small lists use multiple -d
    for h in hostnames:
        cmd.extend(["-d", h])
    return cmd


def _parse_dnsx_jsonl(text: str) -> list[DnsResult]:
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
                    results_by_host[host].records.append(DnsRecord(
                        hostname=host,
                        record_type=rt.upper(),
                        value=v,
                        ttl=data.get("ttl", 0),
                    ))
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
    raw_path = await _save_raw("dnsx", ",".join(hostnames), result.stdout, result.stderr, engagement_id)

    results = _parse_dnsx_jsonl(result.stdout)
    log.info("dnsx_done", hostnames=len(hostnames), resolved=len(results), duration=result.duration_sec)

    return DnsOutput(
        results=results,
        raw_output_path=raw_path,
        command=result.command,
        duration_sec=result.duration_sec,
    )
