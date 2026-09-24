"""AutoRed sqlmap tool wrapper — Phase 3, Task 3.

Runs sqlmap for SQL injection testing against a target URL with parameters.
Parses stdout for injection points (Parameter / Type / Title / Payload
blocks), the back-end DBMS string, and a vulnerable/not-vulnerable flag.

Reuses ``_save_raw`` from ``autored.tools.nmap`` (Task 7) so every tool
wrapper persists raw artefacts via the same path scheme.

Decorator order note (Ruling 1 in the SDD ledger): ``@tool`` is applied
OUTERMOST and ``@roe_guard`` INNER. The opposite order produces a
StructuredTool that is not callable via ``.ainvoke({...})`` at runtime —
see Batch A review.
"""
from __future__ import annotations

import re

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.subprocess_runner import run_subprocess
from autored.tools.nmap import _save_raw  # reuse from nmap

log = get_logger("tools.sqlmap")


class InjectionPoint(BaseModel):
    parameter: str
    method: str  # GET, POST, etc.
    type: str  # boolean-based blind, time-based blind, etc.
    title: str
    payload: str


class SqlmapResult(BaseModel):
    url: str
    vulnerable: bool = False
    injection_points: list[InjectionPoint] = Field(default_factory=list)
    dbms: str | None = None
    raw_output_path: str = ""
    command: str = ""
    duration_sec: float = 0.0


def _build_sqlmap_cmd(
    url: str, options: list[str] | None, output_dir: str | None
) -> list[str]:
    """Build a sqlmap argv list.

    ``--batch`` is mandatory so sqlmap never blocks on interactive prompts
    (the LLM-driven loop has no stdin for it to read from). ``--output-dir``
    is only added when an engagement-scoped path is supplied.
    """
    cmd: list[str] = ["sqlmap", "-u", url, "--batch"]
    if options:
        cmd.extend(options)
    if output_dir:
        cmd.extend(["--output-dir", output_dir])
    return cmd


# Multi-line regex matching a Parameter / Type / Title / Payload block as
# emitted by sqlmap. The terminator is the next blank line (``\n\n``), the
# block separator (``\n---``), or end-of-text (``\Z``). DOTALL so the
# greedy-ish ``.+?`` captures across the indented multi-line payload.
_INJECTION_PATTERN = re.compile(
    r"Parameter:\s*(\S+)\s+\((\w+)\)\s*\n"
    r"\s*Type:\s*(.+?)\n"
    r"\s*Title:\s*(.+?)\n"
    r"\s*Payload:\s*(.+?)(?:\n\n|\n---|\Z)",
    re.DOTALL,
)
_DBMS_PATTERN = re.compile(r"back-end DBMS:\s*(.+)")

# sqlmap's "not vulnerable" message contains the substring "injectable"
# ("all tested parameters do not appear to be injectable"), which collides
# with the simple positive "injectable" substring check the brief
# originally spec'd. Treat the explicit negative phrase as an override
# before applying the positive check so the not-vulnerable path stays
# clean.
_NOT_INJECTABLE_PHRASES = (
    "do not appear to be injectable",
    "not injectable",
    "does not appear to be injectable",
    "all tested parameters do not appear to be injectable",
)


def _parse_sqlmap_output(text: str, url: str) -> SqlmapResult:
    """Parse sqlmap stdout into a SqlmapResult.

    Sets ``vulnerable`` based on the presence of "injection point" or
    "injectable" in the text — except when the explicit not-vulnerable
    message is also present, which overrides to False. Extracts the
    ``back-end DBMS:`` line and any Parameter/Type/Title/Payload blocks.
    """
    result = SqlmapResult(url=url)
    text_lower = text.lower()

    # Negative override first — sqlmap's not-vulnerable banner contains
    # the word "injectable", which would otherwise be a false positive.
    if any(phrase in text_lower for phrase in _NOT_INJECTABLE_PHRASES):
        result.vulnerable = False
    elif "injectable" in text_lower or "injection point" in text_lower:
        result.vulnerable = True

    dbms_match = _DBMS_PATTERN.search(text)
    if dbms_match:
        result.dbms = dbms_match.group(1).strip()

    for match in _INJECTION_PATTERN.finditer(text):
        result.injection_points.append(
            InjectionPoint(
                parameter=match.group(1),
                method=match.group(2),
                type=match.group(3).strip(),
                title=match.group(4).strip(),
                payload=match.group(5).strip(),
            )
        )

    return result


@tool
@roe_guard(allowed_categories=["exploit"])
async def sqlmap_run(
    url: str,
    options: list[str] | None = None,
    engagement_id: str = "",
) -> SqlmapResult:
    """Run sqlmap for SQL injection testing.

    Args:
        url: Target URL with parameters (e.g., http://target/page?id=1)
        options: Additional sqlmap options (e.g., ["--forms", "--level=3"])
        engagement_id: Current engagement ID

    Returns:
        SqlmapResult with vulnerability status and injection points.
    """
    output_dir = (
        f"engagements/{engagement_id}/evidence/sqlmap"
        if engagement_id
        else None
    )
    cmd = _build_sqlmap_cmd(url, options, output_dir)
    log.info("sqlmap_start", url=url, options=options)

    result = await run_subprocess(cmd, timeout=600)
    raw_path = await _save_raw(
        "sqlmap", url, result.stdout, result.stderr, engagement_id
    )

    parsed = _parse_sqlmap_output(result.stdout, url)
    parsed.raw_output_path = raw_path
    parsed.command = result.command
    parsed.duration_sec = result.duration_sec

    log.info(
        "sqlmap_done",
        url=url,
        vulnerable=parsed.vulnerable,
        injections=len(parsed.injection_points),
    )
    return parsed
