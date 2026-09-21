"""AutoRed Phase 4 — Persistence tool wrappers.

Five persistence method tools (3 Linux + 2 Windows) that build the
command for installing a persistence foothold on a compromised host
and — Review Focus #3 — every tool returns a
:class:`PersistenceArtifact` with a non-empty ``removal_command``
that the Phase 5 Cleanup Agent runs verbatim to tear the foothold
down.

The tools follow the established Phase 4 pattern: a ``_build_*``
helper returns ``(cmd_tokens, removal_command)``, the ``@tool
@roe_guard(allowed_categories=["persistence"])`` wrapper builds a
:class:`PersistenceArtifact` from that pair, and the actual
execution is delegated to the Phase 6 foothold session manager
(this module only constructs commands and artifacts; it does not
execute anything on a remote host).

Linux methods:
    * ``cron_modify``        — append an entry to the user crontab.
    * ``systemd_create``     — drop a unit file under
      ``/etc/systemd/system/`` and enable + start it.
    * ``ssh_key_add``        — append a public key to
      ``~/.ssh/authorized_keys``.

Windows methods:
    * ``schtasks_create``    — ``schtasks /create`` for a scheduled task.
    * ``reg_modify``         — ``reg add`` for a Run-key (or any
      autorun) value.
"""
from langchain_core.tools import tool
from pydantic import BaseModel

from autored.logging import get_logger
from autored.models.postex import PersistenceArtifact
from autored.roe_guard import roe_guard

log = get_logger("tools.persistence")


class PersistenceResult(BaseModel):
    """Result of a persistence tool invocation.

    ``artifact`` is always populated on success and carries the
    ``removal_command`` the Phase 5 Cleanup Agent will run verbatim.
    """

    method: str
    host_ip: str
    success: bool = False
    artifact: PersistenceArtifact | None = None
    raw_output: str = ""
    duration_sec: float = 0.0


# --------------------------------------------------------------------------- #
# Removal command builders
# --------------------------------------------------------------------------- #
def _removal_cron(command: str) -> str:
    """Build the crontab removal command.

    Strips any crontab entry whose command portion matches ``command``
    by piping the existing crontab through ``grep -v`` and re-installing
    it. The Cleanup Agent runs this verbatim on the Linux foothold.
    """
    return f"crontab -l | grep -v '{command}' | crontab -"


def _removal_schtasks(task_name: str) -> str:
    """Build the schtasks removal command (delete + force)."""
    return f"schtasks /delete /tn {task_name} /f"


def _removal_reg(key_path: str, value_name: str) -> str:
    """Build the reg-delete removal command for a Run-key value."""
    return f"reg delete {key_path} /v {value_name} /f"


def _removal_systemd(service_name: str) -> str:
    """Build the systemd-unit removal command (stop + disable + rm)."""
    return (
        f"systemctl stop {service_name} "
        f"&& systemctl disable {service_name} "
        f"&& rm -f /etc/systemd/system/{service_name}.service "
        f"&& systemctl daemon-reload"
    )


def _removal_ssh_key(comment: str) -> str:
    """Build the authorized_keys removal command (delete the line)."""
    return f"sed -i '/{comment}/d' ~/.ssh/authorized_keys"


# --------------------------------------------------------------------------- #
# Command builders — each returns (cmd_tokens, removal_command)
# --------------------------------------------------------------------------- #
def _build_cron_modify(schedule: str, command: str) -> tuple[list[str], str]:
    """Build the cron persistence command + removal.

    Returns a flat token list representing the shell pipeline
    ``(crontab -l 2>/dev/null; echo '<schedule> <command>') | crontab -``.
    ``schedule`` and ``command`` are kept as discrete tokens so the
    test suite (and the persistence sub-agent's planner) can verify
    each appears in the command — when executed, the tokens are joined
    with spaces and wrapped in ``sh -c`` on the Linux foothold. The
    removal command strips the entry by ``grep -v``-ing ``command``
    out of the crontab.
    """
    cmd = [
        "(crontab", "-l", "2>/dev/null;",
        "echo", schedule, command,
        "|", "crontab", "-)",
    ]
    removal = _removal_cron(command)
    return cmd, removal


def _build_systemd_create(
    service_name: str, command: str,
) -> tuple[list[str], str]:
    """Build a systemd unit-file drop + enable + start command.

    Returns a flat token list whose joined form (wrapped in ``sh -c``)
    writes the unit file, reloads the daemon, and enables + starts the
    service. The removal command stops, disables, and deletes the unit
    file (and reloads the daemon).
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
    joined = (
        f"printf '%s\\n' '{unit_file}' > /etc/systemd/system/{service_name}.service "
        f"&& systemctl daemon-reload "
        f"&& systemctl enable {service_name}.service "
        f"&& systemctl start {service_name}.service"
    )
    cmd = ["sh", "-c", joined]
    removal = _removal_systemd(service_name)
    return cmd, removal


def _build_ssh_key_add(
    public_key: str, comment: str = "autored",
) -> tuple[list[str], str]:
    """Build the authorized_keys append command + removal.

    The ``comment`` is the trailing token of the SSH public key line
    (e.g., ``user@host``) — the removal command greps it out of
    ``~/.ssh/authorized_keys``.
    """
    joined = (
        f"mkdir -p ~/.ssh && chmod 700 ~/.ssh "
        f"&& echo '{public_key}' >> ~/.ssh/authorized_keys "
        f"&& chmod 600 ~/.ssh/authorized_keys"
    )
    cmd = ["sh", "-c", joined]
    removal = _removal_ssh_key(comment)
    return cmd, removal


def _build_schtasks_create(
    task_name: str, command: str, trigger: str = "ONLOGON",
) -> tuple[list[str], str]:
    """Build the schtasks /create command + removal.

    ``trigger`` maps to ``/sc`` (schedule type) — common values are
    ``ONLOGON``, ``ONSTART``, ``MINUTE``, ``HOURLY``, ``DAILY``. The
    removal command is ``schtasks /delete /tn <name> /f``.
    """
    cmd = [
        "schtasks", "/create",
        "/tn", task_name,
        "/tr", command,
        "/sc", trigger,
        "/f",
    ]
    removal = _removal_schtasks(task_name)
    return cmd, removal


def _build_reg_modify(
    key_path: str, value_name: str, value_data: str,
) -> tuple[list[str], str]:
    """Build the reg add command + removal.

    Writes a ``REG_SZ`` value (the typical autorun shape) under
    ``key_path``. The removal command is ``reg delete <key> /v <name> /f``.
    """
    cmd = [
        "reg", "add", key_path,
        "/v", value_name,
        "/t", "REG_SZ",
        "/d", value_data,
        "/f",
    ]
    removal = _removal_reg(key_path, value_name)
    return cmd, removal


# --------------------------------------------------------------------------- #
# Tools — each builds the command, constructs a PersistenceArtifact
# with the removal_command, and returns a PersistenceResult. Actual
# execution is delegated to the Phase 6 foothold session manager.
# --------------------------------------------------------------------------- #
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

    Appends ``<schedule> <command>`` to the current user's crontab.
    The artifact's ``removal_command`` strips the entry by
    ``grep -v``-ing ``command`` out of the crontab.

    Args:
        schedule: Cron schedule expression (e.g., "@reboot", "*/5 * * * *").
        command: Shell command for cron to execute.
        host_ip: Target host IP.
        foothold_id: Foothold establishing persistence.
        engagement_id: Current engagement ID.

    Returns:
        PersistenceResult with a PersistenceArtifact (includes
        removal_command).
    """
    cmd, removal = _build_cron_modify(schedule, command)
    log.info("cron_modify", host_ip=host_ip, schedule=schedule)
    artifact = PersistenceArtifact(
        host_ip=host_ip,
        method="cron",
        details={
            "schedule": schedule,
            "command": command,
            "command_built": " ".join(cmd),
        },
        removal_command=removal,
        foothold_id=foothold_id,
    )
    return PersistenceResult(
        method="cron", host_ip=host_ip, success=True, artifact=artifact,
    )


@tool
@roe_guard(allowed_categories=["persistence"])
async def systemd_create(
    service_name: str,
    command: str,
    host_ip: str,
    foothold_id: str,
    engagement_id: str = "",
) -> PersistenceResult:
    """Establish systemd service persistence on a Linux foothold.

    Drops a unit file at ``/etc/systemd/system/<service_name>.service``
    with ``ExecStart=<command>`` and ``Restart=always``, then reloads
    the daemon and enables + starts the service. The artifact's
    ``removal_command`` stops, disables, and deletes the unit file.

    Args:
        service_name: Service unit name (without ``.service`` suffix).
        command: ``ExecStart`` command for the unit.
        host_ip: Target host IP.
        foothold_id: Foothold establishing persistence.
        engagement_id: Current engagement ID.

    Returns:
        PersistenceResult with a PersistenceArtifact (includes
        removal_command).
    """
    cmd, removal = _build_systemd_create(service_name, command)
    log.info("systemd_create", host_ip=host_ip, service_name=service_name)
    artifact = PersistenceArtifact(
        host_ip=host_ip,
        method="systemd",
        details={
            "service_name": service_name,
            "command": command,
            "command_built": " ".join(cmd),
        },
        removal_command=removal,
        foothold_id=foothold_id,
    )
    return PersistenceResult(
        method="systemd", host_ip=host_ip, success=True, artifact=artifact,
    )


@tool
@roe_guard(allowed_categories=["persistence"])
async def ssh_key_add(
    public_key: str,
    host_ip: str,
    foothold_id: str,
    comment: str = "autored",
    engagement_id: str = "",
) -> PersistenceResult:
    """Establish SSH authorized_keys persistence on a Linux foothold.

    Appends ``public_key`` to ``~/.ssh/authorized_keys``. The
    artifact's ``removal_command`` deletes any line containing
    ``comment`` from the file.

    Args:
        public_key: SSH public key line to append.
        host_ip: Target host IP.
        foothold_id: Foothold establishing persistence.
        comment: Comment token to grep out on removal (defaults to
            "autored"; should match the trailing token of
            ``public_key``).
        engagement_id: Current engagement ID.

    Returns:
        PersistenceResult with a PersistenceArtifact (includes
        removal_command).
    """
    cmd, removal = _build_ssh_key_add(public_key, comment)
    log.info("ssh_key_add", host_ip=host_ip, comment=comment)
    artifact = PersistenceArtifact(
        host_ip=host_ip,
        method="ssh_authorized_keys",
        details={
            "public_key": public_key,
            "comment": comment,
            "command_built": " ".join(cmd),
        },
        removal_command=removal,
        foothold_id=foothold_id,
    )
    return PersistenceResult(
        method="ssh_authorized_keys",
        host_ip=host_ip,
        success=True,
        artifact=artifact,
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

    Runs ``schtasks /create /tn <task_name> /tr <command> /sc <trigger> /f``.
    The artifact's ``removal_command`` is
    ``schtasks /delete /tn <task_name> /f``.

    Args:
        task_name: Scheduled task name.
        command: Command the task will execute.
        trigger: Schedule type (e.g., "ONLOGON", "ONSTART", "MINUTE").
        host_ip: Target host IP.
        foothold_id: Foothold establishing persistence.
        engagement_id: Current engagement ID.

    Returns:
        PersistenceResult with a PersistenceArtifact (includes
        removal_command).
    """
    cmd, removal = _build_schtasks_create(task_name, command, trigger)
    log.info("schtasks_create", host_ip=host_ip, task_name=task_name)
    artifact = PersistenceArtifact(
        host_ip=host_ip,
        method="scheduled_task",
        details={
            "task_name": task_name,
            "command": command,
            "trigger": trigger,
            "command_built": " ".join(cmd),
        },
        removal_command=removal,
        foothold_id=foothold_id,
    )
    return PersistenceResult(
        method="scheduled_task",
        host_ip=host_ip,
        success=True,
        artifact=artifact,
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

    Runs ``reg add <key_path> /v <value_name> /t REG_SZ /d <value_data> /f``.
    The artifact's ``removal_command`` is
    ``reg delete <key_path> /v <value_name> /f``.

    Args:
        key_path: Registry key path (e.g.,
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run").
        value_name: Value name to write.
        value_data: Value data (the autorun command).
        host_ip: Target host IP.
        foothold_id: Foothold establishing persistence.
        engagement_id: Current engagement ID.

    Returns:
        PersistenceResult with a PersistenceArtifact (includes
        removal_command).
    """
    cmd, removal = _build_reg_modify(key_path, value_name, value_data)
    log.info("reg_modify", host_ip=host_ip, key_path=key_path, value_name=value_name)
    artifact = PersistenceArtifact(
        host_ip=host_ip,
        method="registry_run",
        details={
            "key_path": key_path,
            "value_name": value_name,
            "value_data": value_data,
            "command_built": " ".join(cmd),
        },
        removal_command=removal,
        foothold_id=foothold_id,
    )
    return PersistenceResult(
        method="registry_run",
        host_ip=host_ip,
        success=True,
        artifact=artifact,
    )
