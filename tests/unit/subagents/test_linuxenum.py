# tests/unit/subagents/test_linuxenum.py
import pytest
from unittest.mock import AsyncMock, patch

from autored.subagents.linuxenum import linuxenum_subagent, LinuxEnumOutput
from autored.tools.linpeas import LinpeasResult


@pytest.mark.asyncio
async def test_linuxenum_wraps_linpeas():
    """LinuxEnum sub-agent wraps linpeas_run and returns its result."""
    fake_result = LinpeasResult(
        host_ip="10.10.10.5",
        suid_binaries=["/usr/bin/find"],
        cves=["CVE-2021-4034"],
        cron_jobs=["*/5 * * * * root /opt/backup.sh"],
        sudo_entries=["(ALL) NOPASSWD: /usr/bin/find"],
        raw_output_path="/tmp/raw/linpeas.out",
        command="curl -sL ... | sh",
    )
    with patch("autored.subagents.linuxenum.linpeas_run") as mock_linpeas:
        mock_linpeas.ainvoke = AsyncMock(return_value=fake_result)

        result = await linuxenum_subagent.ainvoke({
            "foothold_id": "f1",
            "host_ip": "10.10.10.5",
            "engagement_id": "test-eng",
        })

    assert isinstance(result, LinuxEnumOutput)
    assert result.host_ip == "10.10.10.5"
    assert result.linpeas_result is not None
    assert "CVE-2021-4034" in result.linpeas_result.cves
    assert result.linpeas_result.sudo_entries == [
        "(ALL) NOPASSWD: /usr/bin/find",
    ]
    # ainvoke must be called with the wrapped tool's input dict
    mock_linpeas.ainvoke.assert_awaited_once()
