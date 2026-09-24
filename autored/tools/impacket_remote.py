"""Impacket remote-execution tools (wmiexec / psexec / smbexec).

Phase 5 lateral-movement workhorses (spec §5.3 + §9.2). Unlike the
Phase 4 foothold-shell tools (linpeas/mimikatz/secretsdump build a
command string for a future session manager to replay), impacket's
remote-exec tools run **on the AutoRed host** and talk to the target
over SMB — so a pivot via these tools is fully functional today,
given credentials and network reachability.

All three share one command builder and one parser — the impacket
remote-exec family has a uniform CLI (``<tool>.py [-hashes :nthash]
user[:pass]@target command``) and uniform failure markers
(``STATUS_LOGON_FAILURE``, ``SessionError``, ``[-]`` stderr lines).

Decorator order (Ruling 1): ``@tool`` OUTER, ``@roe_guard`` INNER — see
``autored.tools.hydra`` for the rationale and the regression tests in
``test_<tool>_ainvoke_works_with_roe_guard``.

Spec ref: §5.3 (tool table), §6.8 (RoE guard), §9.2 (PivotRecord.method
Literal across wmiexec/psexec/smbexec).
"""
from __future__ import annotations

from typing import Literal

from langchain_core.tools import tool
from pydantic import BaseModel

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.subprocess_runner import SubprocessResult, run_subprocess
from autored.tools.nmap import _save_raw

log = get_logger("tools.impacket_remote")


class ImpacketRemoteResult(BaseModel):
    """Result of one remote command via an impacket remote-exec channel."""

    host_ip: str
    method: Literal["wmiexec", "psexec", "smbexec"]
    command_executed: str
    output: str
    success: bool
    raw_output_path: str = ""
    duration_sec: float = 0.0


def _build_impacket_cmd(
    tool_name: str,
    username: str,
    password: str,
    nthash: str,
    target: str,
    command: str,
) -> list[str]:
    """Build ``<tool>.py`` argv for wmiexec/psexec/smbexec.

    With an NTLM hash, impacket expects ``-hashes :<nthash>`` and a
    bare ``user@target`` (pass-the-hash). With a password it expects
    ``user:password@target``. Never mixes the two.
    """
    cmd = [f"{tool_name}.py"]
    if nthash:
        cmd += ["-hashes", f":{nthash}", f"{username}@{target}"]
    else:
        cmd += [f"{username}:{password}@{target}"]
    cmd += [command]
    return cmd


def _parse_impacket_output(
    result: SubprocessResult,
    host_ip: str,
    method: str,
    command: str,
    raw_path: str,
) -> ImpacketRemoteResult:
    """Parse an impacket remote-exec subprocess result.

    Failure markers: nonzero returncode, ``STATUS_LOGON_FAILURE``,
    ``SessionError``, or a leading ``[-]`` error line in stderr — the
    impacket family's uniform failure surface.
    """
    text = result.stdout + result.stderr
    failed = (
        result.returncode != 0
        or "STATUS_LOGON_FAILURE" in text
        or "SessionError" in text
        or "[-]" in result.stderr
    )
    return ImpacketRemoteResult(
        host_ip=host_ip,
        method=method,
        command_executed=command,
        output=result.stdout,
        success=not failed,
        raw_output_path=raw_path,
        duration_sec=result.duration_sec,
    )


async def _run_impacket_remote(
    tool_name: str,
    username: str,
    password: str,
    nthash: str,
    target: str,
    command: str,
    engagement_id: str,
) -> ImpacketRemoteResult:
    """Shared body for the three @tool entrypoints."""
    cmd = _build_impacket_cmd(tool_name, username, password, nthash, target, command)
    log.info(
        "impacket_remote",
        tool=tool_name,
        target=target,
        auth="nthash" if nthash else "password",
    )
    result = await run_subprocess(cmd, timeout=300)
    raw_path = await _save_raw(
        tool_name, target, result.stdout, result.stderr, engagement_id
    )
    return _parse_impacket_output(result, target, tool_name, command, raw_path)


@tool
@roe_guard(allowed_categories=["lateral"])
async def impacket_wmiexec(
    username: str,
    password: str,
    nthash: str,
    target: str,
    command: str,
    engagement_id: str = "",
) -> ImpacketRemoteResult:
    """Run a command on a Windows target via impacket wmiexec (WMI over DCOM).

    Args:
        username: Account to authenticate as.
        password: Plaintext password (empty when using a hash).
        nthash: NTLM hash for pass-the-hash (empty when using a password).
        target: Target IP (must be within the engagement's allowed_ips).
        command: Remote command to execute (e.g. "whoami").
        engagement_id: Current engagement ID.

    Returns:
        ImpacketRemoteResult — ``success`` False on logon failure /
        session errors.
    """
    return await _run_impacket_remote(
        "wmiexec", username, password, nthash, target, command, engagement_id,
    )


@tool
@roe_guard(allowed_categories=["lateral"])
async def impacket_psexec(
    username: str,
    password: str,
    nthash: str,
    target: str,
    command: str,
    engagement_id: str = "",
) -> ImpacketRemoteResult:
    """Run a command on a Windows target via impacket psexec (RemComSvc over SMB)."""
    return await _run_impacket_remote(
        "psexec", username, password, nthash, target, command, engagement_id,
    )


@tool
@roe_guard(allowed_categories=["lateral"])
async def impacket_smbexec(
    username: str,
    password: str,
    nthash: str,
    target: str,
    command: str,
    engagement_id: str = "",
) -> ImpacketRemoteResult:
    """Run a command on a Windows target via impacket smbexec (SMBExec / svcexec)."""
    return await _run_impacket_remote(
        "smbexec", username, password, nthash, target, command, engagement_id,
    )
