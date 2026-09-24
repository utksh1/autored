"""AutoRed gobuster vhost tool wrapper — Phase 1, Task 15.

Runs gobuster in ``vhost`` mode for virtual host discovery and parses
findings into a ``VhostList`` Pydantic model.

Reuses ``_save_raw`` from ``autored.tools.nmap`` (Task 7) so every tool
wrapper persists raw artefacts via the same path scheme.

Decorator order note (Ruling 1 in the SDD ledger): ``@tool`` is applied
OUTERMOST and ``@roe_guard`` INNER. The brief spec'd the opposite order
(``@roe_guard`` over ``@tool``), but that produces a StructuredTool that
is not callable via ``.ainvoke({...})`` at runtime — see Batch A review.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.subprocess_runner import run_subprocess
from autored.tools.nmap import _save_raw  # reuse from nmap

log = get_logger("tools.gobuster_vhost")


class VhostEntry(BaseModel):
    hostname: str
    status_code: int
    content_length: int = 0


class VhostList(BaseModel):
    domain: str
    vhosts: list[VhostEntry] = Field(default_factory=list)
    raw_output_path: str = ""
    command: str = ""
    duration_sec: float = 0.0


DEFAULT_VHOST_WORDLIST = (
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
)

# Lines look like: "Found: dev.lame.htb            Status: 200    [Size: 1234]"
_VHOST_PATTERN = re.compile(
    r"Found:\s+(\S+)\s+Status:\s+(\d+)\s+\[Size:\s+(\d+)\]"
)


def _build_gobuster_cmd(url: str, wordlist: str) -> list[str]:
    """Build a gobuster vhost argv list."""
    return ["gobuster", "vhost", "-u", url, "-w", wordlist, "--no-error", "-q"]


def _parse_gobuster_output(text: str, domain: str) -> VhostList:
    """Parse gobuster vhost stdout into a VhostList.

    Uses ``re.search`` per line so we tolerate gobuster's leading
    whitespace and any trailing progress noise (``-q`` suppresses most of
    it, but extra logging lines are skipped silently if they don't match
    the pattern).
    """
    vhosts: list[VhostEntry] = []
    for line in text.splitlines():
        m = _VHOST_PATTERN.search(line)
        if m:
            vhosts.append(
                VhostEntry(
                    hostname=m.group(1),
                    status_code=int(m.group(2)),
                    content_length=int(m.group(3)),
                )
            )
    return VhostList(domain=domain, vhosts=vhosts)


@tool
@roe_guard(allowed_categories=["recon", "read_only"])
async def gobuster_vhost(
    url: str,
    wordlist: str = DEFAULT_VHOST_WORDLIST,
    engagement_id: str = "",
) -> VhostList:
    """Run gobuster vhost for virtual host discovery.

    Args:
        url: Target URL (e.g., http://lame.htb)
        wordlist: Path to vhost wordlist
        engagement_id: Current engagement ID

    Returns:
        VhostList with discovered virtual hosts
    """
    # Extract domain from URL for the result
    domain = urlparse(url).hostname or url

    cmd = _build_gobuster_cmd(url, wordlist)
    log.info("gobuster_vhost_start", url=url)

    result = await run_subprocess(cmd, timeout=300)
    raw_path = await _save_raw(
        "gobuster_vhost", url, result.stdout, result.stderr, engagement_id
    )

    parsed = _parse_gobuster_output(result.stdout, domain)
    parsed.raw_output_path = raw_path
    parsed.command = result.command
    parsed.duration_sec = result.duration_sec

    log.info(
        "gobuster_vhost_done",
        url=url,
        vhosts=len(parsed.vhosts),
        duration=result.duration_sec,
    )
    return parsed
