"""Tests for the LinuxEnum sub-agent (Phase 4, Task 8).

Verifies that ``linuxenum_subagent`` is a thin wrapper around
``linpeas_run.ainvoke({"foothold_id", "host_ip", "engagement_id"})`` and
surfaces the parsed ``LinpeasResult`` on a ``LinuxEnumOutput``. The
Phase 4 stub leaves the ``users`` / ``secrets`` / ``privesc_candidates``
lists empty — Phase 5's LLM post-processing pass will populate them.
"""
from unittest.mock import AsyncMock, patch

import pytest

from autored.subagents.linuxenum import LinuxEnumOutput, linuxenum_subagent
from autored.tools.linpeas import LinpeasResult


@pytest.mark.asyncio
async def test_linuxenum_wraps_linpeas_run():
    """Happy path: linpeas returns a LinpeasResult → LinuxEnumOutput surfaces it."""
    fake_result = LinpeasResult(
        host_ip="10.10.10.5",
        suid_binaries=["/usr/bin/find"],
        cves=["CVE-2021-4034"],
        raw_output_path="/tmp/fake/linpeas.out",
    )
    with patch("autored.subagents.linuxenum.linpeas_run") as mock_linpeas:
        mock_linpeas.ainvoke = AsyncMock(return_value=fake_result)
        result = await linuxenum_subagent.ainvoke({
            "foothold_id": "fh-001",
            "host_ip": "10.10.10.5",
            "engagement_id": "test-eng",
        })
    assert isinstance(result, LinuxEnumOutput)
    assert result.host_ip == "10.10.10.5"
    assert result.linpeas_result is fake_result
    mock_linpeas.ainvoke.assert_awaited_once()


@pytest.mark.asyncio
async def test_linuxenum_passes_engagement_id_through():
    """engagement_id is threaded down to linpeas_run so the raw artefact
    path is namespaced per engagement (audit-trail contract)."""
    captured = {}

    async def fake_ainvoke(payload):
        captured.update(payload)
        return LinpeasResult(host_ip=payload["host_ip"])

    with patch("autored.subagents.linuxenum.linpeas_run") as mock_linpeas:
        mock_linpeas.ainvoke = fake_ainvoke
        await linuxenum_subagent.ainvoke({
            "foothold_id": "fh-001",
            "host_ip": "10.10.10.5",
            "engagement_id": "eng-42",
        })
    assert captured["engagement_id"] == "eng-42"
    assert captured["foothold_id"] == "fh-001"
    assert captured["host_ip"] == "10.10.10.5"


@pytest.mark.asyncio
async def test_linuxenum_phase4_stub_leaves_postex_lists_empty():
    """Phase 4 contract: users / secrets / privesc_candidates lists are
    empty by default — Phase 5 LLM post-processing will populate them
    from the parsed linpeas sections."""
    with patch("autored.subagents.linuxenum.linpeas_run") as mock_linpeas:
        mock_linpeas.ainvoke = AsyncMock(
            return_value=LinpeasResult(host_ip="10.10.10.5")
        )
        result = await linuxenum_subagent.ainvoke({
            "foothold_id": "fh-001",
            "host_ip": "10.10.10.5",
            "engagement_id": "test-eng",
        })
    assert result.users == []
    assert result.secrets == []
    assert result.privesc_candidates == []
