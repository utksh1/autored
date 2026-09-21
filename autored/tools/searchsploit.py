"""Searchsploit (ExploitDB CLI) query tool.

Wraps the local ``searchsploit`` CLI shipped with ExploitDB. Used by the Vuln
Agent (Phase 2) to find public exploit code matching a product+version or
keyword query. The CLI is invoked with ``--json`` so output is structured;
each exploit entry is parsed into an :class:`ExploitEntry` and the raw
stdout/stderr is preserved via the shared ``_save_raw`` helper for forensic
review. If the CLI is not installed or returns non-JSON output the tool
returns an empty :class:`SearchsploitResult` rather than raising — the
pipeline treats "no exploits" and "searchsploit unavailable" identically.
"""
import json

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.subprocess_runner import run_subprocess
from autored.tools.nmap import _save_raw

log = get_logger("tools.searchsploit")


class ExploitEntry(BaseModel):
    edb_id: str
    title: str
    author: str = ""
    date: str = ""
    type: str = ""
    platform: str = ""
    path: str = ""


class SearchsploitResult(BaseModel):
    query: str
    exploits: list[ExploitEntry] = Field(default_factory=list)
    raw_output_path: str = ""
    command: str = ""
    duration_sec: float = 0.0


def _build_searchsploit_cmd(query: str) -> list[str]:
    """Build the searchsploit CLI invocation list."""
    return ["searchsploit", "--json", query]


def _parse_searchsploit_json(data: dict, query: str) -> SearchsploitResult:
    """Parse the ``{"RESULTS_SEARCH": [...]}`` payload from searchsploit --json."""
    exploits = []
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
        SearchsploitResult with matching exploits from ExploitDB.
    """
    cmd = _build_searchsploit_cmd(query)
    log.info("searchsploit_start", query=query)

    result = await run_subprocess(cmd, timeout=60)
    raw_path = await _save_raw(
        "searchsploit", query, result.stdout, result.stderr, engagement_id
    )

    try:
        data = json.loads(result.stdout)
        parsed = _parse_searchsploit_json(data, query)
    except json.JSONDecodeError as e:
        log.error("searchsploit_parse_failed", query=query, error=str(e))
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
