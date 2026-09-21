import pytest
from unittest.mock import AsyncMock, patch
from autored.subagents.webenum import webenum_subagent, WebEnumOutput
from autored.tools.httpx_tool import HttpxOutput, HttpxResult
from autored.tools.feroxbuster import FeroxbusterOutput, DirResult
from autored.tools.nuclei import NucleiOutput, NucleiResult


@pytest.mark.asyncio
async def test_webenum_returns_all_results():
    fake_httpx = HttpxOutput(results=[HttpxResult(
        url="http://10.10.10.5", status_code=200, tech_stack=["Apache"],
    )])
    fake_ferox = FeroxbusterOutput(target_url="http://10.10.10.5",
        results=[DirResult(url="http://10.10.10.5/admin", status_code=200)])
    fake_nuclei = NucleiOutput(target="http://10.10.10.5", results=[])

    with patch("autored.subagents.webenum.httpx_probe") as mock_httpx, \
         patch("autored.subagents.webenum.feroxbuster_dir") as mock_ferox, \
         patch("autored.subagents.webenum.nuclei_scan") as mock_nuclei:
        mock_httpx.ainvoke = AsyncMock(return_value=fake_httpx)
        mock_ferox.ainvoke = AsyncMock(return_value=fake_ferox)
        mock_nuclei.ainvoke = AsyncMock(return_value=fake_nuclei)

        result = await webenum_subagent.ainvoke({
            "url": "http://10.10.10.5",
            "engagement_id": "test-eng",
        })

    assert isinstance(result, WebEnumOutput)
    assert len(result.httpx_results) == 1
    assert len(result.directories) == 1
    assert result.nuclei_results == []


@pytest.mark.asyncio
async def test_webenum_skips_when_no_web_service():
    fake_httpx = HttpxOutput(results=[])

    with patch("autored.subagents.webenum.httpx_probe") as mock_httpx, \
         patch("autored.subagents.webenum.feroxbuster_dir") as mock_ferox, \
         patch("autored.subagents.webenum.nuclei_scan") as mock_nuclei:
        mock_httpx.ainvoke = AsyncMock(return_value=fake_httpx)
        mock_ferox.ainvoke = AsyncMock(return_value=None)
        mock_nuclei.ainvoke = AsyncMock(return_value=None)

        result = await webenum_subagent.ainvoke({
            "url": "http://10.10.10.5",
            "engagement_id": "test-eng",
        })

    assert isinstance(result, WebEnumOutput)
    assert result.httpx_results == []
    assert result.directories == []
    assert result.nuclei_results == []
    # ferox/nuclei must NOT be called when httpx finds no web service
    mock_ferox.ainvoke.assert_not_called()
    mock_nuclei.ainvoke.assert_not_called()
