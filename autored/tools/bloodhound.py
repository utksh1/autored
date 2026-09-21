from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.subprocess_runner import run_subprocess
from autored.tools.nmap import _save_raw

log = get_logger("tools.bloodhound")


class BloodhoundResult(BaseModel):
    domain: str
    host: str
    json_output_path: str = ""
    computers: list[dict] = Field(default_factory=list)
    users: list[dict] = Field(default_factory=list)
    sessions: list[dict] = Field(default_factory=list)
    raw_output_path: str = ""
    command: str = ""
    duration_sec: float = 0.0


def _build_bloodhound_cmd(
    username: str, password: str, domain: str, host: str,
) -> list[str]:
    """Build the bloodhound-python collection command.

    Uses ``-ns <host>`` for the DNS resolver (DC IP) and ``-c All`` to
    collect every collection method (users, groups, computers, sessions,
    ACLs, etc.).
    """
    return [
        "bloodhound-python",
        "-u", username,
        "-p", password,
        "-d", domain,
        "-ns", host,
        "-c", "All",
    ]


@tool
@roe_guard(allowed_categories=["read_only"])
async def bloodhound_collect(
    username: str,
    password: str,
    domain: str,
    host: str,
    engagement_id: str = "",
) -> BloodhoundResult:
    """Collect BloodHound data from an AD environment.

    Runs ``bloodhound-python -c All`` against the target domain controller
    and saves the resulting JSON output as raw evidence. The collected
    JSON files are imported into Neo4j via ``Neo4jStore.upload_bloodhound_data``
    in a later step.

    Args:
        username: AD username
        password: AD password
        domain: Domain FQDN (e.g., "CORP.LOCAL")
        host: Domain controller IP (used as the DNS resolver via -ns)
        engagement_id: Current engagement ID

    Returns:
        BloodhoundResult with the path to the collected JSON data.
    """
    cmd = _build_bloodhound_cmd(username, password, domain, host)
    log.info("bloodhound_start", domain=domain, host=host)

    result = await run_subprocess(cmd, timeout=600)
    raw_path = await _save_raw(
        "bloodhound", host, result.stdout, result.stderr, engagement_id,
    )

    log.info(
        "bloodhound_done",
        domain=domain, host=host,
        returncode=result.returncode, duration=result.duration_sec,
    )
    return BloodhoundResult(
        domain=domain,
        host=host,
        json_output_path=raw_path,
        raw_output_path=raw_path,
        command=result.command,
        duration_sec=result.duration_sec,
    )
