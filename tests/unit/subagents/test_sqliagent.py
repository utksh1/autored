import pytest
from unittest.mock import AsyncMock, patch
from autored.subagents.sqliagent import sqliagent_subagent
from autored.tools.sqlmap import SqlmapResult, InjectionPoint


@pytest.mark.asyncio
async def test_sqliagent_calls_sqlmap():
    fake_result = SqlmapResult(
        url="http://10.10.10.5/page?id=1",
        vulnerable=True,
        injection_points=[InjectionPoint(
            parameter="id", method="GET", type="boolean-based blind",
            title="test", payload="id=1 AND 1=1",
        )],
        dbms="MySQL",
    )
    with patch("autored.subagents.sqliagent.sqlmap_run") as mock_sqlmap:
        mock_sqlmap.ainvoke = AsyncMock(return_value=fake_result)
        result = await sqliagent_subagent.ainvoke({
            "url": "http://10.10.10.5/page?id=1",
            "engagement_id": "test",
        })
    assert result.vulnerable is True
    assert len(result.injection_points) == 1
