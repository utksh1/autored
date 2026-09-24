"""Tests for the customagent sub-agent (Phase 3, Task 8).

Verifies that ``customagent_subagent`` is a thin wrapper around
``custom_command.ainvoke({...})`` and faithfully returns the
``CustomResult`` (stdout, returncode, success flag).
"""
import pytest
from unittest.mock import AsyncMock, patch

from autored.subagents.customagent import customagent_subagent
from autored.tools.custom import CustomResult


@pytest.mark.asyncio
async def test_customagent_executes_command():
    fake_result = CustomResult(
        command="whoami", stdout="root\n", returncode=0, success=True,
    )
    with patch("autored.subagents.customagent.custom_command") as mock_custom:
        mock_custom.ainvoke = AsyncMock(return_value=fake_result)
        result = await customagent_subagent.ainvoke({
            "command": "whoami",
            "engagement_id": "test",
        })
    assert result.success is True
    assert "root" in result.stdout
