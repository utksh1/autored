"""AutoRed subfinder tool wrapper — Phase 1, Task 12.

Runs subfinder for passive subdomain enumeration with JSON output and
parses findings into a ``SubdomainList`` Pydantic model.

Reuses ``_save_raw`` from ``autored.tools.nmap`` (Task 7) so every tool
wrapper persists raw artefacts via the same path scheme.

Decorator order note (Ruling 1 in the SDD ledger): ``@tool`` is applied
OUTERMOST and ``@roe_guard`` INNER. The brief spec'd the opposite order
(``@roe_guard`` over ``@tool``), but that produces a StructuredTool that
is not callable via ``.ainvoke({...})`` at runtime — see Batch A review.
"""
from __future__ import annotations

import json

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.subprocess_runner import run_subprocess
from autored.tools.nmap import _save_raw  # reuse from nmap

log = get_logger("tools.subfinder")


class SubdomainList(BaseModel):
    domain: str
    subdomains: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    raw_output_path: str = ""
    command: str = ""
    duration_sec: float = 0.0


def _build_subfinder_cmd(domain: str) -> list[str]:
    """Build a subfinder argv list. Output goes to stdout as JSONL."""
    return ["subfinder", "-d", domain, "-json", "-silent"]


def _parse_subfinder_jsonl(text: str, domain: str) -> SubdomainList:
    """Parse subfinder JSONL stdout into a SubdomainList.

    The fixture file is ``subfinder_lame.json`` (``.json`` extension) but
    the content is JSONL — one JSON object per line — matching what the
    real subfinder binary emits with ``-json``.

    Skips blank/malformed lines silently (subfinder emits a lot of noise).
    Deduplicates subdomains while preserving first-seen order.
    """
    subdomains: list[str] = []
    sources: list[str] = []
    for line in text.strip().splitlines():
        if not line:
            continue
        try:
            data = json.loads(line)
            host = data.get("host", "")
            if host:
                subdomains.append(host)
            source = data.get("source", "")
            if source and source not in sources:
                sources.append(source)
        except json.JSONDecodeError:
            continue
    # Dedupe while preserving order
    seen: set[str] = set()
    unique_subs: list[str] = []
    for s in subdomains:
        if s not in seen:
            seen.add(s)
            unique_subs.append(s)
    return SubdomainList(domain=domain, subdomains=unique_subs, sources=sources)


@tool
@roe_guard(allowed_categories=["recon", "read_only"])
async def subfinder_enum(
    domain: str,
    engagement_id: str = "",
) -> SubdomainList:
    """Run subfinder for passive subdomain enumeration.

    Args:
        domain: Root domain (e.g., "example.com")
        engagement_id: Current engagement ID

    Returns:
        SubdomainList with discovered subdomains
    """
    cmd = _build_subfinder_cmd(domain)
    log.info("subfinder_start", domain=domain)

    result = await run_subprocess(cmd, timeout=120)
    raw_path = await _save_raw(
        "subfinder", domain, result.stdout, result.stderr, engagement_id
    )

    parsed = _parse_subfinder_jsonl(result.stdout, domain)
    parsed.raw_output_path = raw_path
    parsed.command = result.command
    parsed.duration_sec = result.duration_sec

    log.info(
        "subfinder_done",
        domain=domain,
        subdomains=len(parsed.subdomains),
        duration=result.duration_sec,
    )
    return parsed
