from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.subprocess_runner import run_subprocess
from autored.tools.nmap import _save_raw

log = get_logger("tools.certipy")


class CertipyResult(BaseModel):
    action: str
    target: str
    vulnerable_templates: list[dict] = Field(default_factory=list)
    raw_output_path: str = ""
    command: str = ""
    duration_sec: float = 0.0


def _build_certipy_cmd(
    action: str,
    username: str,
    password: str,
    domain: str,
    target: str,
) -> list[str]:
    """Build the certipy command for the given action.

    Examples:
        certipy find -u user@CORP.LOCAL -p pass -dc-ip 10.10.10.5
        certipy auth -u user@CORP.LOCAL -p pass -dc-ip 10.10.10.5
    """
    return [
        "certipy",
        action,
        "-u", f"{username}@{domain}",
        "-p", password,
        "-dc-ip", target,
    ]


@tool
@roe_guard(allowed_categories=["read_only"])
async def certipy(
    action: str,
    username: str,
    password: str,
    domain: str,
    target: str,
    engagement_id: str = "",
) -> CertipyResult:
    """Run a certipy action against an AD CS environment.

    The most common action is ``find`` (enumeration of vulnerable
    certificate templates — ESC1 through ESC15). Runs ``certipy`` on
    the AutoRed host and saves stdout as raw evidence. Vulnerable
    template parsing from certipy's JSON output will be added in a
    follow-up; for now the result carries an empty list.

    Args:
        action: certipy subcommand (e.g., "find", "auth", "req")
        username: AD username
        password: AD password
        domain: Domain FQDN (e.g., "CORP.LOCAL")
        target: Domain controller IP
        engagement_id: Current engagement ID

    Returns:
        CertipyResult with the action, target, and raw output path.
    """
    cmd = _build_certipy_cmd(action, username, password, domain, target)
    log.info("certipy_start", action=action, target=target, domain=domain)

    result = await run_subprocess(cmd, timeout=300)
    raw_path = await _save_raw(
        "certipy", target, result.stdout, result.stderr, engagement_id,
    )

    log.info(
        "certipy_done",
        action=action, target=target,
        returncode=result.returncode, duration=result.duration_sec,
    )
    return CertipyResult(
        action=action,
        target=target,
        vulnerable_templates=[],
        raw_output_path=raw_path,
        command=result.command,
        duration_sec=result.duration_sec,
    )
