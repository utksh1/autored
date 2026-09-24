"""Unit tests for the ArtifactRemover sub-agent (Phase 5 Task 8)."""
from unittest.mock import AsyncMock, patch

from autored.subagents.artifactremover import artifactremover_subagent
from autored.models.cleanup import CleanupResult
from autored.models.postex import PersistenceArtifact
from autored.tools.cleanup import CleanupExecutionResult

_HOST_PLAN = {
    "host_ip": "192.168.56.22",
    "artifact_ids": ["a-1", "a-2"],
    "removal_commands": ["schtasks /delete /tn AutoRedUpdate /f"],
    "tunnel_teardowns": [],
    "temp_files": [],
    "transport": "impacket_wmiexec",
    "username": "administrator",
    "password": "",
    "nthash": "abc123",
}


def _artifact(aid: str) -> dict:
    return PersistenceArtifact(
        id=aid, host_ip="192.168.56.22", method="scheduled_task",
        details={"task_name": "AutoRedUpdate", "command": "powershell -enc x"},
        removal_command="schtasks /delete /tn AutoRedUpdate /f",
        foothold_id="f-1",
    ).model_dump()


def _exec_result(success=True):
    return CleanupExecutionResult(
        host_ip="192.168.56.22",
        removal_command="schtasks /delete /tn AutoRedUpdate /f",
        transport="impacket_wmiexec",
        success=success, output="SUCCESS: The scheduled task was deleted.",
        error=None if success else "STATUS_LOGON_FAILURE",
    )


async def test_removes_all_artifacts():
    artifacts = [_artifact("a-1"), _artifact("a-2")]
    with patch("autored.subagents.artifactremover.cleanup_execute") as mock_exec:
        mock_exec.ainvoke = AsyncMock(return_value=_exec_result())
        out = await artifactremover_subagent.ainvoke({
            "host_plan": _HOST_PLAN, "artifacts": artifacts,
            "engagement_id": "e1",
        })
    assert len(out.results) == 2
    assert all(r.success and not r.verified for r in out.results)
    # credentials passed through from the host plan
    exec_args = mock_exec.ainvoke.call_args.kwargs
    assert exec_args["nthash"] == "abc123"
    assert exec_args["transport"] == "impacket_wmiexec"
    # removal command passed verbatim from the artifact
    assert exec_args["removal_command"].startswith("schtasks /delete")


async def test_failed_removal_recorded_with_error():
    """Review Focus #5: failed removal → success=False, error set,
    verified=False. Never silently green."""
    artifacts = [_artifact("a-1")]
    with patch("autored.subagents.artifactremover.cleanup_execute") as mock_exec:
        mock_exec.ainvoke = AsyncMock(return_value=_exec_result(success=False))
        out = await artifactremover_subagent.ainvoke({
            "host_plan": _HOST_PLAN, "artifacts": artifacts,
            "engagement_id": "e1",
        })
    assert len(out.results) == 1
    r = out.results[0]
    assert r.success is False
    assert r.verified is False
    assert r.error == "STATUS_LOGON_FAILURE"


async def test_empty_artifact_list_is_noop():
    with patch("autored.subagents.artifactremover.cleanup_execute") as mock_exec:
        out = await artifactremover_subagent.ainvoke({
            "host_plan": _HOST_PLAN, "artifacts": [],
            "engagement_id": "e1",
        })
    assert out.results == []
    mock_exec.ainvoke.assert_not_called()
