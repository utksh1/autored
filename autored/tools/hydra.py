import re
from pydantic import BaseModel, Field
from langchain_core.tools import tool
from autored.roe_guard import roe_guard
from autored.subprocess_runner import run_subprocess
from autored.tools.nmap import _save_raw
from autored.logging import get_logger

log = get_logger("tools.hydra")


class BruteCredential(BaseModel):
    username: str
    password: str


class BruteResult(BaseModel):
    target: str
    service: str
    success: bool = False
    credentials: list[BruteCredential] = Field(default_factory=list)
    raw_output_path: str = ""
    command: str = ""
    duration_sec: float = 0.0


def _build_hydra_cmd(target: str, service: str, users_file: str, pass_file: str) -> list[str]:
    return ["hydra", "-L", users_file, "-P", pass_file, "-f", f"{service}://{target}"]


def _parse_hydra_output(text: str, target: str, service: str) -> BruteResult:
    result = BruteResult(target=target, service=service)
    # Check success — hydra's success line is "N of N target successfully completed,
    # M valid passwords found". We need M > 0 for a real success.
    if "successfully completed" in text and "0 valid passwords" not in text:
        result.success = True
    # Extract credentials: [22][ssh] host: 10.10.10.5   login: root   password: toor
    cred_pattern = re.compile(
        r"\[\d+\]\[\w+\]\s+host:\s+\S+\s+login:\s+(\S+)\s+password:\s+(\S+)"
    )
    for match in cred_pattern.finditer(text):
        result.credentials.append(BruteCredential(
            username=match.group(1),
            password=match.group(2),
        ))
    return result


@tool
@roe_guard(allowed_categories=["brute_force"])
async def hydra_brute(
    target: str,
    service: str,
    usernames_file: str,
    passwords_file: str,
    engagement_id: str = "",
) -> BruteResult:
    """Run hydra for brute-force attacks.

    Args:
        target: Target IP or hostname
        service: Service to attack (ssh, ftp, http-post-form, etc.)
        usernames_file: Path to usernames wordlist
        passwords_file: Path to passwords wordlist
        engagement_id: Current engagement ID

    Returns:
        BruteResult with found credentials.
    """
    cmd = _build_hydra_cmd(target, service, usernames_file, passwords_file)
    log.info("hydra_start", target=target, service=service)

    result = await run_subprocess(cmd, timeout=3600)  # brute force can take long
    raw_path = await _save_raw("hydra", target, result.stdout, result.stderr, engagement_id)

    parsed = _parse_hydra_output(result.stdout, target, service)
    parsed.raw_output_path = raw_path
    parsed.command = result.command
    parsed.duration_sec = result.duration_sec

    log.info("hydra_done", target=target, success=parsed.success, creds=len(parsed.credentials))
    return parsed
