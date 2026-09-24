"""Tests for the WindowsEnum sub-agent (Phase 4, Task 8).

Verifies that ``windowsenum_subagent`` is a thin wrapper around
``winpeas_run.ainvoke({"foothold_id", "host_ip", "engagement_id"})`` and
surfaces the parsed ``WinpeasResult`` on a ``WindowsEnumOutput``.
"""
from unittest.mock import AsyncMock, patch

import pytest

from autored.subagents.windowsenum import WindowsEnumOutput, windowsenum_subagent
from autored.tools.winpeas import WinpeasResult


@pytest.mark.asyncio
async def test_windowsenum_wraps_winpeas_run():
    """Happy path: winpeas returns a WinpeasResult → WindowsEnumOutput surfaces it."""
    fake_result = WinpeasResult(
        host_ip="10.10.10.5",
        autologon_credentials=[{"username": "admin", "password": "P@ss", "domain": "CORP"}],
        modifiable_services=["VulnSvc"],
        unattended_files=["C:\\Windows\\Panther\\unattend.xml"],
        raw_output_path="/tmp/fake/winpeas.out",
    )
    with patch("autored.subagents.windowsenum.winpeas_run") as mock_winpeas:
        mock_winpeas.ainvoke = AsyncMock(return_value=fake_result)
        result = await windowsenum_subagent.ainvoke({
            "foothold_id": "fh-001",
            "host_ip": "10.10.10.5",
            "engagement_id": "test-eng",
        })
    assert isinstance(result, WindowsEnumOutput)
    assert result.host_ip == "10.10.10.5"
    assert result.winpeas_result is fake_result
    mock_winpeas.ainvoke.assert_awaited_once()


@pytest.mark.asyncio
async def test_windowsenum_passes_engagement_id_through():
    """engagement_id is threaded down to winpeas_run (audit-trail contract)."""
    captured = {}

    async def fake_ainvoke(payload):
        captured.update(payload)
        return WinpeasResult(host_ip=payload["host_ip"])

    with patch("autored.subagents.windowsenum.winpeas_run") as mock_winpeas:
        mock_winpeas.ainvoke = fake_ainvoke
        await windowsenum_subagent.ainvoke({
            "foothold_id": "fh-001",
            "host_ip": "10.10.10.5",
            "engagement_id": "eng-42",
        })
    assert captured["engagement_id"] == "eng-42"
    assert captured["foothold_id"] == "fh-001"
    assert captured["host_ip"] == "10.10.10.5"


@pytest.mark.asyncio
async def test_windowsenum_phase4_stub_leaves_postex_lists_empty():
    """Phase 4 contract: users / secrets / privesc_candidates lists empty."""
    with patch("autored.subagents.windowsenum.winpeas_run") as mock_winpeas:
        mock_winpeas.ainvoke = AsyncMock(
            return_value=WinpeasResult(host_ip="10.10.10.5")
        )
        result = await windowsenum_subagent.ainvoke({
            "foothold_id": "fh-001",
            "host_ip": "10.10.10.5",
            "engagement_id": "test-eng",
        })
    assert result.users == []
    assert result.secrets == []
    assert result.privesc_candidates == []
