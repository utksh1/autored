"""Unit tests for the VerificationScanner sub-agent (Phase 5 Task 9)."""
from unittest.mock import AsyncMock, patch

from autored.subagents.verificationscanner import verificationscanner_subagent
from autored.models.postex import PersistenceArtifact
from autored.tools.cleanup import CleanupVerificationResult


def _artifact(method: str = "scheduled_task", details: dict | None = None) -> dict:
    return PersistenceArtifact(
        id="a-1", host_ip="192.168.56.22", method=method,
        details=details if details is not None else {"task_name": "AutoRedUpdate"},
        removal_command="schtasks /delete /tn AutoRedUpdate /f",
        foothold_id="f-1",
    ).model_dump()


_HOST_PLAN = {
    "host_ip": "192.168.56.22", "artifact_ids": ["a-1"],
    "removal_commands": [], "tunnel_teardowns": [], "temp_files": [],
    "transport": "impacket_wmiexec", "username": "administrator",
    "password": "", "nthash": "abc123",
}


def _verify_result(verified: bool, output: str) -> CleanupVerificationResult:
    return CleanupVerificationResult(
        host_ip="192.168.56.22",
        verify_command='schtasks /query /tn "AutoRedUpdate"',
        transport="impacket_wmiexec",
        verified=verified, output=output,
    )


async def test_verified_absence():
    with patch("autored.subagents.verificationscanner.cleanup_verify") as mock_v:
        mock_v.ainvoke = AsyncMock(return_value=_verify_result(
            True, "ERROR: The system cannot find the file specified.",
        ))
        out = await verificationscanner_subagent.ainvoke({
            "host_plan": _HOST_PLAN, "artifacts": [_artifact()],
            "engagement_id": "e1",
        })
    assert len(out.results) == 1
    assert out.results[0].verified is True
    assert out.results[0].error is None
    # verify command built from the artifact's method + details
    v_args = mock_v.ainvoke.call_args.kwargs
    assert "schtasks /query" in v_args["verify_command"]
    assert "AutoRedUpdate" in v_args["verify_command"]
    assert v_args["method"] == "scheduled_task"


async def test_artifact_still_present_marks_unverified_with_error():
    """Review Focus #5: still-present artifact → verified=False and an
    error message — visible in the final state, never silently green."""
    with patch("autored.subagents.verificationscanner.cleanup_verify") as mock_v:
        mock_v.ainvoke = AsyncMock(return_value=_verify_result(
            False, "TaskName: AutoRedUpdate  Next Run: ...",
        ))
        out = await verificationscanner_subagent.ainvoke({
            "host_plan": _HOST_PLAN, "artifacts": [_artifact()],
            "engagement_id": "e1",
        })
    assert out.results[0].verified is False
    assert out.results[0].error is not None
    assert "still present" in out.results[0].error


async def test_registry_artifact_uses_reg_query():
    art = _artifact("registry_run", {"key_path": "HKCU\\...\\Run", "value_name": "AutoRed"})
    with patch("autored.subagents.verificationscanner.cleanup_verify") as mock_v:
        mock_v.ainvoke = AsyncMock(return_value=_verify_result(True, "not found"))
        await verificationscanner_subagent.ainvoke({
            "host_plan": _HOST_PLAN, "artifacts": [art], "engagement_id": "e1",
        })
    v_args = mock_v.ainvoke.call_args.kwargs
    assert "reg query" in v_args["verify_command"]
    assert "AutoRed" in v_args["verify_command"]
