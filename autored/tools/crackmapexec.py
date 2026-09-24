"""crackmapexec tool wrapper (Phase 5, spec §5.3).

Spec §5.3: ``crackmapexec {protocol} {target} -u {users} -H {hashes}``.
Used by the PivotExecutor sub-agent as the credential-validation spray
before opening an impacket remote-exec channel: a hash or password
that fails CME auth will fail wmiexec too, so CME is the cheap probe.

The modern binary is sometimes shipped as ``nxc``/``netexec``, but the
spec pins ``crackmapexec`` and Kali still aliases it — keep the spec
name; operators with only ``netexec`` installed can symlink it.

Decorator order (Ruling 1): ``@tool`` OUTER, ``@roe_guard`` INNER — see
``autored.tools.hydra`` for the rationale and the regression test in
``test_crackmapexec_ainvoke_works_with_roe_guard``.
"""
from __future__ import annotations

import re

from langchain_core.tools import tool
from pydantic import BaseModel

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.subprocess_runner import SubprocessResult, run_subprocess
from autored.tools.nmap import _save_raw

log = get_logger("tools.crackmapexec")


class CrackmapexecResult(BaseModel):
    """Result of one crackmapexec credential spray."""

    host_ip: str
    protocol: str
    username: str
    success: bool      # authentication succeeded
    pwned: bool        # admin-level access (the "Pwn3d!" marker)
    output: str
    raw_output_path: str = ""
    duration_sec: float = 0.0


_PWNED_RE = re.compile(r"Pwn3d!")


def _build_cme_cmd(
    protocol: str,
    target: str,
    username: str,
    password: str,
    nthash: str,
) -> list[str]:
    """Build the crackmapexec argv.

    Hash auth and password auth are mutually exclusive — hash wins when
    both are supplied, mirroring the pass-the-hash priority in the
    impacket builder. The empty LM-hash position in the
    ``-hashes :<nthash>`` form is intentional — CME expects the bare
    NT hash here (no LM component, no leading colon).
    """
    cmd = ["crackmapexec", protocol, target, "-u", username]
    if nthash:
        cmd += ["-H", nthash]
    elif password:
        cmd += ["-p", password]
    return cmd


def _parse_cme_output(
    result: SubprocessResult,
    host_ip: str,
    protocol: str,
    username: str,
    raw_path: str,
) -> CrackmapexecResult:
    """Parse crackmapexec output.

    ``Pwn3d!`` → authenticated with admin rights. A bare ``[+]`` line
    without ``Pwn3d!`` → authenticated as a regular user.
    ``STATUS_LOGON_FAILURE`` or nonzero returncode → auth failed.
    """
    text = result.stdout + result.stderr
    pwned = bool(_PWNED_RE.search(text))
    auth_ok = "[+]" in text and "STATUS_LOGON_FAILURE" not in text
    success = (pwned or auth_ok) and result.returncode == 0
    return CrackmapexecResult(
        host_ip=host_ip,
        protocol=protocol,
        username=username,
        success=success,
        pwned=pwned,
        output=result.stdout,
        raw_output_path=raw_path,
        duration_sec=result.duration_sec,
    )


@tool
@roe_guard(allowed_categories=["lateral"])
async def crackmapexec(
    protocol: str,
    target: str,
    username: str,
    password: str = "",
    nthash: str = "",
    engagement_id: str = "",
) -> CrackmapexecResult:
    """Validate credentials against a target via crackmapexec.

    Args:
        protocol: One of "smb", "winrm", "ssh", "ldap", "mssql".
        target: Target IP (must be within the engagement's allowed_ips).
        username: Account to spray.
        password: Plaintext password (empty when using a hash).
        nthash: NTLM hash for pass-the-hash (empty when using a password).
        engagement_id: Current engagement ID.

    Returns:
        CrackmapexecResult — ``success`` is authentication success;
        ``pwned`` is True only for admin-level access.
    """
    cmd = _build_cme_cmd(protocol, target, username, password, nthash)
    log.info("crackmapexec", protocol=protocol, target=target, user=username)
    result = await run_subprocess(cmd, timeout=180)
    raw_path = await _save_raw(
        "crackmapexec", target, result.stdout, result.stderr, engagement_id,
    )
    return _parse_cme_output(result, target, protocol, username, raw_path)
