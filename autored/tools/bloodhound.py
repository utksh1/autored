"""AutoRed BloodHound collection tool wrapper — Phase 4, Task 4.

``bloodhound-python`` is the Python ingest CLI from the BloodHound project
that pulls users / computers / groups / sessions from a target Active
Directory domain controller over LDAP+RPC and dumps the result as a triplet
of JSON files (``*_computers.json``, ``*_users.json``, ``*_sessions.json``)
ready for import into a BloodHound Neo4j instance.

Unlike the T3 linpeas/winpeas wrappers (which only construct a command
string and save it for the Phase 6 FootholdSessionManager to replay),
``bloodhound_collect`` DOES execute ``run_subprocess`` in Phase 4 —
BloodHound collection runs from the operator's machine, not from the
foothold, so it does not need the foothold shell session. The captured
stdout is persisted via ``_save_raw`` and Phase 5 owns downstream parsing
(``Neo4jStore.upload_bloodhound_data`` + ``query_shortest_path``).

Decorator order (Ruling 1): ``@tool`` OUTER, ``@roe_guard`` INNER — see
``autored.tools.hydra`` for the rationale and the regression test in
``test_bloodhound_collect_ainvoke_works_with_roe_guard``.

Spec ref: §3.4 (post-ex models), §6.8 (RoE guard), §9.2 (RoE categories).
"""
from __future__ import annotations

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.subprocess_runner import run_subprocess
from autored.tools.nmap import _save_raw  # reuse from nmap

log = get_logger("tools.bloodhound")


class BloodhoundResult(BaseModel):
    """Result of a BloodHound collection run.

    The brief defers in-memory parsing of the JSON output to Phase 5
    (``Neo4jStore.upload_bloodhound_data`` walks the triplet + imports it
    into Neo4j). Phase 4 callers receive this with ``computers`` / ``users``
    / ``sessions`` all empty — the only populated fields are the paths to
    the saved stdout and the run metadata.
    """

    domain: str
    host: str
    json_output_path: str = ""
    computers: list[dict] = Field(default_factory=list)
    users: list[dict] = Field(default_factory=list)
    sessions: list[dict] = Field(default_factory=list)
    raw_output_path: str = ""
    duration_sec: float = 0.0


def _build_bloodhound_cmd(
    username: str, password: str, domain: str, host: str
) -> list[str]:
    """Build the ``bloodhound-python`` argv list.

    Flags:
      ``-u`` / ``-p``  — AD credentials to bind with.
      ``-d``          — target domain FQDN (e.g., ``CORP.LOCAL``).
      ``-ns``         — nameserver IP (typically the domain controller).
      ``-c All``      — collection method: pull users, computers, groups,
                         sessions, ACLs, GPOs in a single pass.

    Never returns a shell string — the caller passes this directly to
    ``run_subprocess`` which uses ``asyncio.create_subprocess_exec``
    (no shell, no interpolation).
    """
    return [
        "bloodhound-python",
        "-u",
        username,
        "-p",
        password,
        "-d",
        domain,
        "-ns",
        host,
        "-c",
        "All",
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
    """Collect BloodHound data from an Active Directory environment.

    This is the only Phase 4 tool that actually shells out — BloodHound
    collection runs from the operator's machine against the AD DC, not from
    a foothold. The captured stdout (collection log + JSON file paths) is
    persisted via ``_save_raw``; in-memory parsing of the JSON triplet is
    deferred to Phase 5 (``Neo4jStore.upload_bloodhound_data``).

    Args:
        username: AD username to bind with (e.g., ``svc_scan``).
        password: AD password for the bind account.
        domain: Domain FQDN (e.g., ``CORP.LOCAL``).
        host: Domain controller IP (passed via ``-ns`` as the nameserver).
        engagement_id: Current engagement ID for raw output storage + RoE
            registry lookup.

    Returns:
        ``BloodhoundResult`` with ``json_output_path`` and ``raw_output_path``
        set (stdout saved), ``duration_sec`` from the subprocess run, and
        ``computers`` / ``users`` / ``sessions`` empty (Phase 4 defers
        parsing to Phase 5).
    """
    cmd = _build_bloodhound_cmd(username, password, domain, host)
    log.info(
        "bloodhound_start",
        domain=domain,
        host=host,
        username=username,
        # NOTE: never log the password — even at DEBUG. The brief's parser
        # is the only thing that needs to know it, and it is already in the
        # argv list passed to run_subprocess.
    )

    result = await run_subprocess(cmd, timeout=600)
    raw_path = await _save_raw(
        "bloodhound", host, result.stdout, result.stderr, engagement_id
    )

    log.info(
        "bloodhound_done",
        domain=domain,
        host=host,
        returncode=result.returncode,
        duration_sec=result.duration_sec,
    )

    # Phase 4: no in-memory parsing — computers/users/sessions stay empty
    # (Phase 5 Neo4jStore.upload_bloodhound_data walks the JSON triplet).
    return BloodhoundResult(
        domain=domain,
        host=host,
        json_output_path=raw_path,
        raw_output_path=raw_path,
        duration_sec=result.duration_sec,
    )
