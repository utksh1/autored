"""AutoRed searchsploit tool wrapper — Phase 2, Task 5.

Wraps the ``searchsploit`` CLI (ExploitDB offline mirror) with JSON output
and parses the response into a ``SearchsploitResult`` Pydantic model.

Reuses ``_save_raw`` from ``autored.tools.nmap`` (Task 7) so every tool
wrapper persists raw artefacts via the same path scheme.

Decorator order note (Ruling 1 in the Phase 1 SDD ledger): ``@tool`` is
applied OUTERMOST and ``@roe_guard`` INNER. The brief spec'd the opposite
order (``@roe_guard`` over ``@tool``), but that produces a StructuredTool
that is not callable via ``.ainvoke({...})`` at runtime — see Batch A
review of nmap/nuclei/httpx wrappers. Same pattern as every other Phase 1
tool wrapper.
"""

from __future__ import annotations

import json

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.subprocess_runner import run_subprocess
from autored.tools.nmap import _save_raw  # reuse from nmap

log = get_logger("tools.searchsploit")


class ExploitEntry(BaseModel):
    """One ExploitDB row parsed from the ``RESULTS_SEARCH`` array."""

    edb_id: str
    title: str
    author: str = ""
    date: str = ""
    type: str = ""
    platform: str = ""
    path: str = ""


class SearchsploitResult(BaseModel):
    """Parsed result of a ``searchsploit --json <query>`` invocation."""

    query: str
    exploits: list[ExploitEntry] = Field(default_factory=list)
    raw_output_path: str = ""
    command: str = ""
    duration_sec: float = 0.0


def _build_searchsploit_cmd(query: str) -> list[str]:
    """Build a searchsploit argv list. ``--json`` for structured stdout.

    The query string is appended verbatim as a single positional argument
    (searchsploit treats everything after the flags as the search term).
    Never returns a shell string — the caller passes this directly to
    ``asyncio.create_subprocess_exec``.
    """
    return ["searchsploit", "--json", query]


def _parse_searchsploit_json(data: dict, query: str) -> SearchsploitResult:
    """Parse searchsploit JSON stdout (``{"RESULTS_SEARCH": [...]}``) into a
    ``SearchsploitResult``.

    Each entry is mapped to an ``ExploitEntry``. The ExploitDB schema uses
    PascalCase keys (``EDB-ID``, ``Date``, ``Title``, ``Path``) — coerced to
    snake_case Pydantic fields here. Missing fields default to empty
    strings, never raise.

    Returns a ``SearchsploitResult`` with ``query=`` set even if the
    ``RESULTS_SEARCH`` array is missing/empty (graceful degradation).
    """
    exploits: list[ExploitEntry] = []
    for entry in data.get("RESULTS_SEARCH", []):
        exploits.append(
            ExploitEntry(
                edb_id=str(entry.get("EDB-ID", "")),
                title=entry.get("Title", ""),
                author=entry.get("Author", ""),
                date=entry.get("Date", ""),
                type=entry.get("Type", ""),
                platform=entry.get("Platform", ""),
                path=entry.get("Path", ""),
            )
        )
    return SearchsploitResult(query=query, exploits=exploits)


@tool
@roe_guard(allowed_categories=["cve_query", "read_only"])
async def searchsploit_query(
    query: str,
    engagement_id: str = "",
) -> SearchsploitResult:
    """Search ExploitDB via searchsploit CLI for matching exploits.

    Args:
        query: Search term (e.g., "nginx 1.17.3", "Apache Shellshock")
        engagement_id: Current engagement ID

    Returns:
        SearchsploitResult with matching exploits from ExploitDB. Empty
        ``exploits`` list (with ``query`` still set) if searchsploit fails
        or emits non-JSON stdout — never raises to the caller.
    """
    cmd = _build_searchsploit_cmd(query)
    log.info("searchsploit_start", query=query, cmd=cmd)

    result = await run_subprocess(cmd, timeout=60)
    raw_path = await _save_raw("searchsploit", query, result.stdout, result.stderr, engagement_id)

    try:
        data = json.loads(result.stdout)
        parsed = _parse_searchsploit_json(data, query)
    except json.JSONDecodeError as e:
        # searchsploit can emit a banner line before JSON when the local
        # ExploitDB mirror is missing or the binary errors out. We still
        # saved the raw artefact above, so the agent can inspect it; here
        # we return an empty result rather than crashing.
        log.error(
            "searchsploit_parse_failed",
            query=query,
            error=str(e),
            stdout_head=result.stdout[:200],
        )
        parsed = SearchsploitResult(query=query)

    parsed.raw_output_path = raw_path
    parsed.command = result.command
    parsed.duration_sec = result.duration_sec

    log.info(
        "searchsploit_done",
        query=query,
        exploits_found=len(parsed.exploits),
        duration=result.duration_sec,
    )
    return parsed
