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
    assert result.vhosts[0].hostname == "dev.lame.htb"
