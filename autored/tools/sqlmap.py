import re
from pathlib import Path
from pydantic import BaseModel, Field
from langchain_core.tools import tool
from autored.roe_guard import roe_guard
from autored.subprocess_runner import run_subprocess
from autored.tools.nmap import _save_raw
from autored.logging import get_logger

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


def _build_sqlmap_cmd(url: str, options: list[str] | None, output_dir: str | None) -> list[str]:
    cmd = ["sqlmap", "-u", url, "--batch"]
    if options:
        cmd.extend(options)
    if output_dir:
        cmd.extend(["--output-dir", output_dir])
    return cmd


def _parse_sqlmap_output(text: str, url: str) -> SqlmapResult:
    result = SqlmapResult(url=url)
    # sqlmap's canonical negative marker ("all tested parameters do not appear
    # to be injectable") contains the substring "injectable", so the negative
    # phrase must be checked first.
    text_lower = text.lower()
    if "do not appear to be injectable" in text_lower:
        result.vulnerable = False
    elif "injection point" in text_lower or "injectable" in text_lower:
        result.vulnerable = True
    # Extract DBMS
    dbms_match = re.search(r"back-end DBMS:\s*(.+)", text)
    if dbms_match:
        result.dbms = dbms_match.group(1).strip()
    # Extract injection points
    # Format:
    #   Parameter: id (GET)
    #       Type: boolean-based blind
    #       Title: AND boolean-based blind - WHERE or HAVING clause
    #       Payload: id=1 AND 1234=1234
    injection_pattern = re.compile(
        r"Parameter:\s*(\S+)\s+\((\w+)\)\s*\n\s*Type:\s*(.+?)\n\s*Title:\s*(.+?)\n\s*Payload:\s*(.+?)(?:\n\n|\n---|\Z)",
        re.DOTALL,
    )
    for match in injection_pattern.finditer(text):
        result.injection_points.append(InjectionPoint(
            parameter=match.group(1),
            method=match.group(2),
            type=match.group(3).strip(),
            title=match.group(4).strip(),
            payload=match.group(5).strip(),
        ))
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
    output_dir = f"engagements/{engagement_id}/evidence/sqlmap" if engagement_id else None
    cmd = _build_sqlmap_cmd(url, options, output_dir)
    log.info("sqlmap_start", url=url)

    result = await run_subprocess(cmd, timeout=600)
    raw_path = await _save_raw("sqlmap", url, result.stdout, result.stderr, engagement_id)

    parsed = _parse_sqlmap_output(result.stdout, url)
    parsed.raw_output_path = raw_path
    parsed.command = result.command
    parsed.duration_sec = result.duration_sec

    log.info("sqlmap_done", url=url, vulnerable=parsed.vulnerable, injections=len(parsed.injection_points))
    return parsed
