# tests/unit/subagents/test_windowsenum.py
import pytest
from unittest.mock import AsyncMock, patch

from autored.subagents.windowsenum import windowsenum_subagent, WindowsEnumOutput
from autored.tools.winpeas import WinpeasResult


@pytest.mark.asyncio
async def test_windowsenum_wraps_winpeas():
    """WindowsEnum sub-agent wraps winpeas_run and returns its result."""
    fake_result = WinpeasResult(
        host_ip="10.10.10.5",
        autologon_credentials=[
            {"domain": "CORP", "username": "admin", "password": "P@ssw0rd!"},
        ],
        modifiable_services=["VulnSvc"],
        unattended_files=["C:\\Windows\\Panther\\unattend.xml"],
        scheduled_tasks=["\\Microsoft\\Windows\\VulnTask"],
        raw_output_path="/tmp/raw/winpeas.out",
        command="curl -sL ... winPEASx64.exe",
    )
    with patch("autored.subagents.windowsenum.winpeas_run") as mock_winpeas:
        mock_winpeas.ainvoke = AsyncMock(return_value=fake_result)

        result = await windowsenum_subagent.ainvoke({
            "foothold_id": "f1",
            "host_ip": "10.10.10.5",
            "engagement_id": "test-eng",
        })

    assert isinstance(result, WindowsEnumOutput)
    assert result.host_ip == "10.10.10.5"
    assert result.winpeas_result is not None
    assert len(result.winpeas_result.autologon_credentials) == 1
    assert result.winpeas_result.autologon_credentials[0]["username"] == "admin"
    mock_winpeas.ainvoke.assert_awaited_once()
