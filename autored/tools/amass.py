import json
from pathlib import Path
from langchain_core.tools import tool
from autored.roe_guard import roe_guard
from autored.subprocess_runner import run_subprocess
from autored.tools.nmap import _save_raw
from autored.tools.subfinder import SubdomainList
from autored.logging import get_logger

log = get_logger("tools.amass")


def _build_amass_cmd(domain: str) -> list[str]:
    return ["amass", "enum", "-passive", "-d", domain, "-json", "-"]


def _parse_amass_jsonl(text: str, domain: str) -> SubdomainList:
    subdomains: list[str] = []
    sources: list[str] = []
    for line in text.strip().splitlines():
        if not line:
            continue
        try:
            data = json.loads(line)
            name = data.get("name", "")
            if name:
                subdomains.append(name)
            source = data.get("source", "")
            if source and source not in sources:
                sources.append(source)
        except json.JSONDecodeError:
            continue
    seen: set[str] = set()
    unique: list[str] = []
    for s in subdomains:
        if s not in seen:
            seen.add(s)
            unique.append(s)
    return SubdomainList(domain=domain, subdomains=unique, sources=sources)


@tool
@roe_guard(allowed_categories=["recon", "read_only"])
async def amass_enum(
    domain: str,
    engagement_id: str = "",
) -> SubdomainList:
    """Run amass in passive mode for deeper subdomain enumeration.

    Args:
        domain: Root domain (e.g., "example.com")
        engagement_id: Current engagement ID

    Returns:
        SubdomainList with discovered subdomains (merged with subfinder results upstream)
    """
    cmd = _build_amass_cmd(domain)
    log.info("amass_start", domain=domain)

    result = await run_subprocess(cmd, timeout=600)
    raw_path = await _save_raw("amass", domain, result.stdout, result.stderr, engagement_id)

    parsed = _parse_amass_jsonl(result.stdout, domain)
    parsed.raw_output_path = raw_path
    parsed.command = result.command
    parsed.duration_sec = result.duration_sec

    log.info("amass_done", domain=domain, subdomains=len(parsed.subdomains), duration=result.duration_sec)
    return parsed
