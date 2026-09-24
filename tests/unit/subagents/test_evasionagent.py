"""Tests for the EvasionAgent sub-agent (Phase 4, Task 10).

Verifies that ``evasionagent_subagent`` runs the three Windows evasion
tools in sequence (``amsi_bypass`` → ``log_clear`` → ``defender_disable``)
and converts each ``EvasionResult`` into an ``EvasionAction`` record so
the Phase 5 Cleanup Agent can audit which evasions were applied.

Each ``EvasionAction`` carries a stable ``id``, the joined ``command``
string (traceability — what was attempted), and a ``success`` flag so
the Report Agent can flag failures for operator review.
"""
from unittest.mock import AsyncMock, patch

import pytest

from autored.subagents.evasionagent import EvasionAgentOutput, evasionagent_subagent
from autored.tools.evasion import EvasionResult


@pytest.mark.asyncio
async def test_evasionagent_runs_all_three_techniques():
    """Happy path: all three evasion tools return success → three
    EvasionActions, all with success=True and non-empty command strings."""
    fake_amsi = EvasionResult(
        technique="amsi_bypass", host_ip="10.10.10.5", success=True,
        command="powershell -c [Reflection.Assembly]::LoadWithPartialName(...) $b.SetValue($null,$true)",
    )
    fake_log = EvasionResult(
        technique="log_clear", host_ip="10.10.10.5", success=True,
        command="powershell -c wevtutil cl Security; wevtutil cl System; wevtutil cl Application",
    )
    fake_def = EvasionResult(
        technique="defender_disable", host_ip="10.10.10.5", success=True,
        command="powershell -c Set-MpPreference -DisableRealtimeMonitoring $true; ...",
    )
    with patch("autored.subagents.evasionagent.amsi_bypass") as mock_amsi, \
         patch("autored.subagents.evasionagent.log_clear") as mock_log, \
         patch("autored.subagents.evasionagent.defender_disable") as mock_def:
        mock_amsi.ainvoke = AsyncMock(return_value=fake_amsi)
        mock_log.ainvoke = AsyncMock(return_value=fake_log)
        mock_def.ainvoke = AsyncMock(return_value=fake_def)
        result = await evasionagent_subagent.ainvoke({
            "host_ip": "10.10.10.5",
            "engagement_id": "test-eng",
        })
    assert isinstance(result, EvasionAgentOutput)
    assert result.host_ip == "10.10.10.5"
    assert len(result.actions) == 3
    # Each action carries the technique, target, success, and command.
    techniques = [a.technique for a in result.actions]
    assert techniques == ["amsi_bypass", "log_clear", "defender_disable"]
    # All three commands are non-empty (traceability contract).
    for action in result.actions:
        assert action.command
        assert action.success is True
        assert action.host_ip == "10.10.10.5"
    mock_amsi.ainvoke.assert_awaited_once()
    mock_log.ainvoke.assert_awaited_once()
    mock_def.ainvoke.assert_awaited_once()


@pytest.mark.asyncio
async def test_evasionagent_records_per_action_success_flag():
    """When an evasion tool reports failure (e.g., Defender is in tamper-
    protection mode), the sub-agent still records the EvasionAction but
    marks ``success=False`` so the Phase 5 Report Agent can flag it for
    operator review."""
    fake_amsi = EvasionResult(
        technique="amsi_bypass", host_ip="10.10.10.5", success=True,
        command="amsi-cmd",
    )
    fake_log = EvasionResult(
        technique="log_clear", host_ip="10.10.10.5", success=False,
        command="log-cmd",
    )
    fake_def = EvasionResult(
        technique="defender_disable", host_ip="10.10.10.5", success=True,
        command="def-cmd",
    )
    with patch("autored.subagents.evasionagent.amsi_bypass") as mock_amsi, \
         patch("autored.subagents.evasionagent.log_clear") as mock_log, \
         patch("autored.subagents.evasionagent.defender_disable") as mock_def:
        mock_amsi.ainvoke = AsyncMock(return_value=fake_amsi)
        mock_log.ainvoke = AsyncMock(return_value=fake_log)
        mock_def.ainvoke = AsyncMock(return_value=fake_def)
        result = await evasionagent_subagent.ainvoke({
            "host_ip": "10.10.10.5",
            "engagement_id": "test-eng",
        })
    assert len(result.actions) == 3
    # The middle action (log_clear) failed — its success flag is preserved.
    assert result.actions[0].success is True
    assert result.actions[1].success is False
    assert result.actions[2].success is True


@pytest.mark.asyncio
async def test_evasionagent_threads_engagement_id_through():
    """engagement_id is threaded down to each evasion tool (audit-trail
    contract — raw artefact path is namespaced per engagement)."""
    captured = []

    async def fake_ainvoke(payload):
        captured.append(payload.copy())
        return EvasionResult(
            technique=payload.get("technique", "x"),
            host_ip=payload["host_ip"], success=True, command="cmd",
        )

    with patch("autored.subagents.evasionagent.amsi_bypass") as mock_amsi, \
         patch("autored.subagents.evasionagent.log_clear") as mock_log, \
         patch("autored.subagents.evasionagent.defender_disable") as mock_def:
        mock_amsi.ainvoke = fake_ainvoke
        mock_log.ainvoke = fake_ainvoke
        mock_def.ainvoke = fake_ainvoke
        await evasionagent_subagent.ainvoke({
            "host_ip": "10.10.10.5",
            "engagement_id": "eng-42",
        })
    assert all(c["engagement_id"] == "eng-42" for c in captured)
    assert all(c["host_ip"] == "10.10.10.5" for c in captured)
