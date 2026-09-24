"""Cleanup tools: execute + verify artifact removal (Phase 5, spec §6.6).

The Cleanup Agent's sub-agents (ArtifactRemover, VerificationScanner)
use these two tools. Removal commands come verbatim from each
``PersistenceArtifact.removal_command`` (recorded at creation time in
Phase 4) and are transported to the host via impacket-wmiexec
(Windows) or sshpass+ssh (Linux) — the same remote-exec channels the
Lateral Agent uses, so cleanup is fully functional given credentials.

"Verified" means the re-scan output **proves absence**: Windows
not-found markers, or a grep-style nonzero exit. A failed removal is
never marked verified (Review Focus #5).

Decorator order (Ruling 1): ``@tool`` OUTER, ``@roe_guard`` INNER — see
``autored.tools.impacket_remote`` for the rationale and the regression
tests in ``test_<tool>_ainvoke_works_with_roe_guard``.

Spec ref: §6.6 (cleanup layer), §6.8 (RoE guard), §9.2 (cleanup result
models — ``CleanupExecutionResult`` / ``CleanupVerificationResult``).
"""
from __future__ import annotations

from typing import Literal

from langchain_core.tools import tool
from pydantic import BaseModel

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.subprocess_runner import SubprocessResult, run_subprocess
from autored.tools.impacket_remote import _build_impacket_cmd
from autored.tools.nmap import _save_raw

log = get_logger("tools.cleanup")


class CleanupExecutionResult(BaseModel):
    """Outcome of executing one removal command on a host."""

    host_ip: str
    removal_command: str
    transport: Literal["impacket_wmiexec", "ssh"]
    success: bool
    output: str
    error: str | None = None
    raw_output_path: str = ""
    duration_sec: float = 0.0


class CleanupVerificationResult(BaseModel):
    """Outcome of one absence re-scan."""

    host_ip: str
    verify_command: str
    transport: Literal["impacket_wmiexec", "ssh"]
    verified: bool
    output: str
    raw_output_path: str = ""


def _build_remote_cmd(
    transport: str,
    host_ip: str,
    username: str,
    password: str,
    nthash: str,
    command: str,
) -> list[str]:
    """Wrap a shell command in a remote transport.

    ``impacket_wmiexec`` → wmiexec.py (Windows targets, supports
    pass-the-hash). ``ssh`` → sshpass + ssh (Linux targets).
    """
    if transport == "ssh":
        return [
            "sshpass", "-p", password,
            "ssh", "-o", "StrictHostKeyChecking=no",
            f"{username}@{host_ip}", command,
        ]
    return _build_impacket_cmd(
        "wmiexec", username, password, nthash, host_ip, command,
    )


# Absence markers per artifact method: the re-scan output containing
# one of these (or a grep-style nonzero exit) proves the artifact is
# gone. Windows markers are matched case-insensitively for safety.
_ABSENCE_MARKERS: dict[str, list[str]] = {
    "scheduled_task": [
        "cannot find the file specified",
        "the system cannot find the file",
        "error: the system cannot find",
    ],
    "registry_run": [
        "unable to find the specified registry key or value",
        "the system was unable to find",
        "cannot find the file specified",
    ],
    "service": [
        "could not find the service",
        "failed to find",
    ],
    # grep-based methods (cron, systemd, ssh_authorized_keys) rely on
    # nonzero exit / empty output rather than error text.
}


def _build_verify_command(method: str, details: dict) -> str:
    """Build the per-method absence-check command for an artifact."""
    if method == "scheduled_task":
        return f'schtasks /query /tn "{details.get("task_name", "")}"'
    if method == "registry_run":
        return (
            f'reg query "{details.get("key_path", "")}" '
            f'/v {details.get("value_name", "")}'
        )
    if method == "cron":
        return f'crontab -l | grep -F "{details.get("command", "")}"'
    if method == "systemd":
        return f'systemctl status {details.get("service_name", "")} || true'
    if method == "ssh_authorized_keys":
        return f'grep -c "{details.get("comment", "autored")}" ~/.ssh/authorized_keys'
    # Unknown / future methods: generic "did the command channel work"
    # probe — never crashes, never silently verifies.
    return "echo autored-verify-probe"


def _artifact_absent(method: str, text: str, returncode: int) -> bool:
    """Decide whether the re-scan output proves the artifact is gone.

    Windows marker methods: absent when a not-found marker appears.
    grep-style methods: absent when the exit code is nonzero (no
    match) or output is empty. Anything still echo-ing artifact
    content (returncode 0 with content) → present.
    """
    lowered = text.lower()
    markers = _ABSENCE_MARKERS.get(method)
    if markers:
        return any(m in lowered for m in markers)
    # grep-style absence: no match (rc != 0) or empty output
    return returncode != 0 or not text.strip()


async def _run_remote(
    cmd: list[str], engagement_id: str, host_ip: str, tool_name: str,
) -> tuple[SubprocessResult, str]:
    """Run a wrapped remote command and persist raw stdout/stderr.

    Shared by ``cleanup_execute`` and ``cleanup_verify`` — both use the
    same transport, the same 180s timeout, and the same raw-saver. The
    only difference is how they interpret the output (success vs.
    verified).
    """
    result = await run_subprocess(cmd, timeout=180)
    raw_path = await _save_raw(
        tool_name, host_ip, result.stdout, result.stderr, engagement_id,
    )
    return result, raw_path


@tool
@roe_guard(allowed_categories=["cleanup"])
async def cleanup_execute(
    host_ip: str,
    removal_command: str,
    transport: str = "impacket_wmiexec",
    username: str = "",
    password: str = "",
    nthash: str = "",
    engagement_id: str = "",
) -> CleanupExecutionResult:
    """Execute one artifact removal command on a host.

    Args:
        host_ip: Host with the artifact (must have engagement creds).
        removal_command: Verbatim from PersistenceArtifact.removal_command.
        transport: "impacket_wmiexec" (Windows) or "ssh" (Linux).
        username: Account to authenticate as.
        password: Plaintext password (empty when using a hash).
        nthash: NTLM hash for pass-the-hash.
        engagement_id: Current engagement ID.

    Returns:
        CleanupExecutionResult — ``success`` False on transport / auth
        failure; the error text is preserved.
    """
    cmd = _build_remote_cmd(
        transport, host_ip, username, password, nthash, removal_command,
    )
    log.info("cleanup_execute", host_ip=host_ip, transport=transport)
    result, raw_path = await _run_remote(
        cmd, engagement_id, host_ip, "cleanup_execute",
    )
    text = result.stdout + result.stderr
    failed = (
        result.returncode != 0
        or "STATUS_LOGON_FAILURE" in text
        or "SessionError" in text
    )
    return CleanupExecutionResult(
        host_ip=host_ip,
        removal_command=removal_command,
        transport=transport,  # type: ignore[arg-type]
        success=not failed,
        output=result.stdout,
        error=(result.stderr or None) if failed else None,
        raw_output_path=raw_path,
        duration_sec=result.duration_sec,
    )


@tool
@roe_guard(allowed_categories=["cleanup"])
async def cleanup_verify(
    host_ip: str,
    verify_command: str,
    method: str,
    transport: str = "impacket_wmiexec",
    username: str = "",
    password: str = "",
    nthash: str = "",
    engagement_id: str = "",
) -> CleanupVerificationResult:
    """Re-scan a host to verify an artifact was removed.

    Args:
        host_ip: Host to re-scan.
        verify_command: From ``_build_verify_command(method, details)``.
        method: The PersistenceArtifact method (drives absence parsing).
        transport: "impacket_wmiexec" (Windows) or "ssh" (Linux).
        username / password / nthash: Engagement credentials for the host.
        engagement_id: Current engagement ID.

    Returns:
        CleanupVerificationResult — ``verified`` is True only when the
        re-scan output proves absence.
    """
    cmd = _build_remote_cmd(
        transport, host_ip, username, password, nthash, verify_command,
    )
    log.info("cleanup_verify", host_ip=host_ip, method=method)
    result, raw_path = await _run_remote(
        cmd, engagement_id, host_ip, "cleanup_verify",
    )
    text = result.stdout + result.stderr
    verified = _artifact_absent(method, text, result.returncode)
    return CleanupVerificationResult(
        host_ip=host_ip,
        verify_command=verify_command,
        transport=transport,  # type: ignore[arg-type]
        verified=verified,
        output=text,
        raw_output_path=raw_path,
    )
