"""Tests for the vhostenum sub-agent (Phase 1, Task 20).

Verifies that ``vhostenum_subagent`` is a thin pass-through wrapper
around ``gobuster_vhost`` that returns the underlying ``VhostList``.
"""
import pytest
from unittest.mock import AsyncMock, patch

from autored.subagents.vhostenum import vhostenum_subagent
from autored.tools.gobuster_vhost import VhostList, VhostEntry


@pytest.mark.asyncio
async def test_vhostenum_passes_through():
    fake_vhosts = VhostList(domain="lame.htb", vhosts=[
        VhostEntry(hostname="dev.lame.htb", status_code=200),
    ])
    with patch("autored.subagents.vhostenum.gobuster_vhost") as mock_gobuster:
        mock_gobuster.ainvoke = AsyncMock(return_value=fake_vhosts)
        result = await vhostenum_subagent.ainvoke({
            "url": "http://lame.htb",
            "engagement_id": "test-eng",
        })
    assert result.domain == "lame.htb"
    assert len(result.vhosts) == 1
