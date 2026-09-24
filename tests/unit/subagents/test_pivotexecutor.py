"""Unit tests for the PivotExecutor sub-agent (Phase 5 Task 6).

Patches the underlying tool wrappers at their canonical module paths
(``autored.subagents.pivotexecutor.crackmapexec`` etc.) — same pattern
as the Phase 4 sub-agent tests.
"""
from unittest.mock import AsyncMock, patch

from autored.subagents.pivotexecutor import pivotexecutor_subagent

_CANDIDATE = {
    "credential_id": "s-1",
    "username": "administrator",
    "cred_type": "hash",
    "secret_value": "31d6cfe0d16ae931b73c59d7e0c089c0",
    "source_host": "192.168.56.22",
    "target_host": "192.168.56.11",
    "method": "wmiexec",
    "confidence": 0.8,
}


def _cme_result(success=True, pwned=True):
    from autored.tools.crackmapexec import CrackmapexecResult
    return CrackmapexecResult(
        host_ip="192.168.56.11", protocol="smb", username="administrator",
        success=success, pwned=pwned, output="SMB ... Pwn3d!",
    )


def _wmi_result(success=True):
    from autored.tools.impacket_remote import ImpacketRemoteResult
    return ImpacketRemoteResult(
        host_ip="192.168.56.11", method="wmiexec", command_executed="whoami",
        output="goaad\\administrator", success=success,
    )


async def test_successful_wmiexec_pivot():
    with patch("autored.subagents.pivotexecutor.crackmapexec") as mock_cme, \
         patch("autored.subagents.pivotexecutor.impacket_wmiexec") as mock_wmi:
        mock_cme.ainvoke = AsyncMock(return_value=_cme_result())
        mock_wmi.ainvoke = AsyncMock(return_value=_wmi_result())
        out = await pivotexecutor_subagent.ainvoke({
            "candidate": _CANDIDATE, "engagement_id": "e1",
        })
    assert out.success is True
    assert out.pivot is not None and out.pivot.success is True
    assert out.pivot.target_host == "192.168.56.11"
    assert out.pivot.credentials_used == ["s-1"]
    # Hash auth: nthash passed through, password empty
    wmi_args = mock_wmi.ainvoke.call_args.kwargs
    assert wmi_args["nthash"] == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert wmi_args["password"] == ""


async def test_failed_credential_validation_returns_failed_pivot():
    with patch("autored.subagents.pivotexecutor.crackmapexec") as mock_cme, \
         patch("autored.subagents.pivotexecutor.impacket_wmiexec") as mock_wmi:
        mock_cme.ainvoke = AsyncMock(return_value=_cme_result(success=False, pwned=False))
        mock_wmi.ainvoke = AsyncMock()
        out = await pivotexecutor_subagent.ainvoke({
            "candidate": _CANDIDATE, "engagement_id": "e1",
        })
    assert out.success is False
    assert out.pivot is not None and out.pivot.success is False
    mock_wmi.ainvoke.assert_not_awaited()  # no channel without valid creds


async def test_password_candidate_uses_password_auth():
    cand = dict(_CANDIDATE, cred_type="password", secret_value="Password1!",
                method="crackmapexec")
    with patch("autored.subagents.pivotexecutor.crackmapexec") as mock_cme:
        mock_cme.ainvoke = AsyncMock(return_value=_cme_result())
        out = await pivotexecutor_subagent.ainvoke({
            "candidate": cand, "engagement_id": "e1",
        })
    assert out.success is True
    cme_args = mock_cme.ainvoke.call_args.kwargs
    assert cme_args["password"] == "Password1!"
    assert cme_args["nthash"] == ""


async def test_psexec_method_dispatch():
    cand = dict(_CANDIDATE, method="psexec")
    with patch("autored.subagents.pivotexecutor.crackmapexec") as mock_cme, \
         patch("autored.subagents.pivotexecutor.impacket_psexec") as mock_ps:
        mock_cme.ainvoke = AsyncMock(return_value=_cme_result())
        mock_ps.ainvoke = AsyncMock(return_value=_wmi_result())
        out = await pivotexecutor_subagent.ainvoke({
            "candidate": cand, "engagement_id": "e1",
        })
    assert out.success is True
    mock_ps.ainvoke.assert_awaited_once()
