"""AutoRed amass tool wrapper — Phase 1, Task 13.

Runs amass in passive mode for deeper subdomain enumeration with JSON
output and parses findings into a ``SubdomainList`` Pydantic model
(reused from Task 12 — subfinder).

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

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.subprocess_runner import run_subprocess
from autored.tools.nmap import _save_raw  # reuse from nmap
from autored.tools.subfinder import SubdomainList  # reuse from subfinder (T12)

log = get_logger("tools.amass")


def _build_amass_cmd(domain: str) -> list[str]:
    """Build an amass argv list. Output goes to stdout as JSONL via ``-json -``."""
    return ["amass", "enum", "-passive", "-d", domain, "-json", "-"]


def _parse_amass_jsonl(text: str, domain: str) -> SubdomainList:
    """Parse amass JSONL stdout into a SubdomainList.

    The fixture file is ``amass_lame.json`` (``.json`` extension) but the
    content is JSONL — one JSON object per line — matching what the real
    amass binary emits with ``-json -``.

    Each amass JSONL record uses the ``name`` field for the discovered
    subdomain (subfinder uses ``host`` — they are not the same shape, hence
    the separate parser). Skips blank/malformed lines silently. Deduplicates
    subdomains while preserving first-seen order.
    """
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
async def amass_enum(
    domain: str,
    engagement_id: str = "",
) -> SubdomainList:
    """Run amass in passive mode for deeper subdomain enumeration.

    Args:
        domain: Root domain (e.g., "example.com")
        engagement_id: Current engagement ID

    Returns:
        SubdomainList with discovered subdomains (merged with subfinder
        results upstream)
    """
    cmd = _build_amass_cmd(domain)
    log.info("amass_start", domain=domain)

    result = await run_subprocess(cmd, timeout=600)
    raw_path = await _save_raw(
        "amass", domain, result.stdout, result.stderr, engagement_id
    )

    parsed = _parse_amass_jsonl(result.stdout, domain)
    parsed.raw_output_path = raw_path
    parsed.command = result.command
    parsed.duration_sec = result.duration_sec

    log.info(
        "amass_done",
        domain=domain,
        subdomains=len(parsed.subdomains),
        duration=result.duration_sec,
    )
    return parsed
