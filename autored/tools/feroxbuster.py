"""AutoRed feroxbuster tool wrapper — Phase 1, Task 11.

Runs feroxbuster for directory/content discovery with JSON output and
parses findings into a list of ``DirResult`` Pydantic models.

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

log = get_logger("tools.feroxbuster")


class DirResult(BaseModel):
    url: str
    status_code: int
    content_length: int = 0
    method: str = "GET"
    extension: str | None = None
    word: str = ""


class FeroxbusterOutput(BaseModel):
    target_url: str
    results: list[DirResult] = Field(default_factory=list)
    raw_output_path: str = ""
    command: str = ""
    duration_sec: float = 0.0


DEFAULT_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"


def _build_feroxbuster_cmd(url: str, wordlist: str, depth: int) -> list[str]:
    """Build a feroxbuster argv list. Output goes to stdout as JSONL."""
    return [
        "feroxbuster",
        "-u",
        url,
        "-w",
        wordlist,
        "-d",
        str(depth),
        "--json",
        "-q",
    ]


def _parse_feroxbuster_jsonl(text: str) -> list[DirResult]:
    """Parse feroxbuster JSONL stdout into a list of DirResult.

    The fixture file is ``feroxbuster_lame.json`` (``.json`` extension) but
    the content is JSONL — one JSON object per line — matching what the
    real feroxbuster binary emits with ``--json``.

    Skips blank/malformed lines (logged at warning) so a single bad line
    doesn't lose the whole sweep.
    """
    results: list[DirResult] = []
    for line in text.strip().splitlines():
        if not line:
            continue
        try:
            data = json.loads(line)
            results.append(
                DirResult(
                    url=data.get("path", data.get("url", "")),
                    status_code=data.get("status", 0),
                    content_length=data.get("content_length", 0),
                    method=data.get("method", "GET"),
                    extension=data.get("extension") or None,
                    word=" ".join(data.get("words", [])),
                )
            )
        except (json.JSONDecodeError, KeyError) as e:
            log.warning(
                "feroxbuster_parse_line_failed", line=line, error=str(e)
            )
    return results


@tool
@roe_guard(allowed_categories=["recon", "read_only"])
async def feroxbuster_dir(
    url: str,
    wordlist: str = DEFAULT_WORDLIST,
    depth: int = 3,
    engagement_id: str = "",
) -> FeroxbusterOutput:
    """Run feroxbuster for directory/content discovery.

    Args:
        url: Target URL (e.g., http://10.10.10.5)
        wordlist: Path to wordlist file
        depth: Maximum recursion depth
        engagement_id: Current engagement ID

    Returns:
        FeroxbusterOutput with list of DirResult
    """
    cmd = _build_feroxbuster_cmd(url, wordlist, depth)
    log.info("feroxbuster_start", url=url, wordlist=wordlist, depth=depth)

    result = await run_subprocess(cmd, timeout=600)
    raw_path = await _save_raw(
        "feroxbuster", url, result.stdout, result.stderr, engagement_id
    )

    results = _parse_feroxbuster_jsonl(result.stdout)
    log.info(
        "feroxbuster_done",
        url=url,
        paths_found=len(results),
        duration=result.duration_sec,
    )

    return FeroxbusterOutput(
        target_url=url,
        results=results,
        raw_output_path=raw_path,
        command=result.command,
        duration_sec=result.duration_sec,
    )
