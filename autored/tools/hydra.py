"""AutoRed hydra tool wrapper — Phase 3, Task 4.

Runs hydra for credential brute-force attacks against a network service.
Parses stdout for found credential pairs and a success flag derived from
the trailing summary line ("N of N target successfully completed, M valid
passwords found").

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


def _build_hydra_cmd(
    target: str, service: str, users_file: str, pass_file: str
) -> list[str]:
    """Build a hydra argv list.

    ``-f`` stops hydra after the first valid credential is found per
    host — the LLM-driven orchestrator wants a quick win to pivot on,
    not an exhaustive wordlist walk. Target is passed as
    ``<service>://<target>`` so hydra routes through the right module.
    """
    return ["hydra", "-L", users_file, "-P", pass_file, "-f", f"{service}://{target}"]


# Match ``[22][ssh] host: 10.10.10.5   login: root   password: toor``
# The leading ``[\d+]`` is the hydra task slot; ``[\w+]`` is the service
# module. Whitespace between fields is collapsed by ``\s+`` so the test
# fixture's multi-space alignment still matches.
_CREDENTIAL_PATTERN = re.compile(
    r"\[\d+\]\[\w+\]\s+host:\s+\S+\s+login:\s+(\S+)\s+password:\s+(\S+)"
)


def _parse_hydra_output(text: str, target: str, service: str) -> BruteResult:
    """Parse hydra stdout into a BruteResult.

    Sets ``success`` only when the trailing summary contains both
    "successfully completed" AND a non-zero valid-passwords count. The
    bare "successfully completed" substring would otherwise be true even
    when hydra walked the entire wordlist without a single hit (the
    summary line in that case is "0 of 1 target successfully completed,
    0 valid passwords found").
    """
    result = BruteResult(target=target, service=service)

    if "successfully completed" in text and "0 valid passwords" not in text:
        result.success = True

    for match in _CREDENTIAL_PATTERN.finditer(text):
        result.credentials.append(
            BruteCredential(
                username=match.group(1),
                password=match.group(2),
            )
        )

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
    raw_path = await _save_raw(
        "hydra", target, result.stdout, result.stderr, engagement_id
    )

    parsed = _parse_hydra_output(result.stdout, target, service)
    parsed.raw_output_path = raw_path
    parsed.command = result.command
    parsed.duration_sec = result.duration_sec

    log.info(
        "hydra_done",
        target=target,
        success=parsed.success,
        creds=len(parsed.credentials),
    )
    return parsed
