# tests/unit/subagents/test_evasionagent.py
import pytest
from unittest.mock import AsyncMock, patch

from autored.models.postex import EvasionAction
from autored.subagents.evasionagent import (
    evasionagent_subagent,
    EvasionAgentOutput,
)
from autored.tools.evasion import EvasionResult


@pytest.mark.asyncio
async def test_evasionagent_runs_three_techniques():
    """EvasionAgent runs amsi_bypass + log_clear + defender_disable on a
    Windows foothold and records each as an EvasionAction."""
    fake_amsi = EvasionResult(
        technique="amsi_bypass",
        host_ip="10.10.10.5",
        success=True,
        command="powershell -NoProfile ... amsiInitFailed",
    )
    fake_log = EvasionResult(
        technique="log_clear",
        host_ip="10.10.10.5",
        success=True,
        command="wevtutil cl Security; wevtutil cl System",
    )
    fake_def = EvasionResult(
        technique="defender_disable",
        host_ip="10.10.10.5",
        success=True,
        command="Set-MpPreference -DisableRealtimeMonitoring $true",
    )

    with patch("autored.subagents.evasionagent.amsi_bypass") as mock_amsi, \
         patch("autored.subagents.evasionagent.log_clear") as mock_log, \
         patch("autored.subagents.evasionagent.defender_disable") as mock_def:
        mock_amsi.ainvoke = AsyncMock(return_value=fake_amsi)
        mock_log.ainvoke = AsyncMock(return_value=fake_log)
        mock_def.ainvoke = AsyncMock(return_value=fake_def)

        result = await evasionagent_subagent.ainvoke({
            "host_ip": "10.10.10.5",
            "engagement_id": "test",
        })

    assert isinstance(result, EvasionAgentOutput)
    assert result.host_ip == "10.10.10.5"
    assert len(result.actions) == 3
    techniques = {a.technique for a in result.actions}
    assert techniques == {"amsi_bypass", "log_clear", "defender_disable"}
    # Every action is an EvasionAction with the command + host recorded.
    for action in result.actions:
        assert isinstance(action, EvasionAction)
        assert action.host_ip == "10.10.10.5"
        assert action.command
        assert action.success is True

    mock_amsi.ainvoke.assert_awaited_once()
    mock_log.ainvoke.assert_awaited_once()
    mock_def.ainvoke.assert_awaited_once()
