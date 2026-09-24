"""Tests for the bruteagent sub-agent (Phase 3, Task 8).

Verifies that ``bruteagent_subagent`` is a thin wrapper around
``hydra_brute.ainvoke({...})`` and faithfully returns the
``BruteResult`` (success flag + credential list).
"""
import pytest
from unittest.mock import AsyncMock, patch

from autored.subagents.bruteagent import bruteagent_subagent
from autored.tools.hydra import BruteResult, BruteCredential


@pytest.mark.asyncio
async def test_bruteagent_calls_hydra():
    fake_result = BruteResult(
        target="10.10.10.5", service="ssh", success=True,
        credentials=[BruteCredential(username="root", password="toor")],
    )
    with patch("autored.subagents.bruteagent.hydra_brute") as mock_hydra:
        mock_hydra.ainvoke = AsyncMock(return_value=fake_result)
        result = await bruteagent_subagent.ainvoke({
            "target": "10.10.10.5", "service": "ssh",
            "usernames_file": "/tmp/users.txt", "passwords_file": "/tmp/pass.txt",
            "engagement_id": "test",
        })
    assert result.success is True
    assert len(result.credentials) == 1
