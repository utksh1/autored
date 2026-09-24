"""Tests for the portscan sub-agent (Phase 1, Task 16).

Verifies that ``portscan_subagent`` chains ``naabu_scan`` (fast sweep) →
``nmap_scan`` (deep service scan on open ports) and returns a
``PortScanOutput`` containing both, with ``deep_scan=None`` when naabu
finds no open ports.
"""
import pytest
from unittest.mock import AsyncMock, patch

from autored.subagents.portscan import portscan_subagent, PortScanOutput
from autored.tools.naabu import PortList, NaabuPort
from autored.tools.nmap import NmapResult, NmapHost, NmapPort


@pytest.mark.asyncio
async def test_portscan_subagent_returns_both_scans():
    # Mock naabu_scan to return open ports
    fake_naabu = PortList(
        target="10.10.10.5",
        ports=[
            NaabuPort(port=21, protocol="tcp", host="10.10.10.5"),
            NaabuPort(port=22, protocol="tcp", host="10.10.10.5"),
        ],
    )
    # Mock nmap_scan to return full service info
    fake_nmap = NmapResult(
        target="10.10.10.5",
        scan_type="service",
        hosts=[NmapHost(
            ip="10.10.10.5",
            ports=[
                NmapPort(port=21, protocol="tcp", state="open", service="ftp",
                         product="vsftpd", version="2.3.4"),
                NmapPort(port=22, protocol="tcp", state="open", service="ssh",
                         product="OpenSSH", version="4.7p1"),
            ],
        )],
    )

    with patch("autored.subagents.portscan.naabu_scan") as mock_naabu, \
         patch("autored.subagents.portscan.nmap_scan") as mock_nmap:
        # naabu_scan is a @tool-wrapped function; mock its ainvoke
        mock_naabu.ainvoke = AsyncMock(return_value=fake_naabu)
        mock_nmap.ainvoke = AsyncMock(return_value=fake_nmap)

        result = await portscan_subagent.ainvoke({
            "target": "10.10.10.5",
            "scan_type": "service",
            "engagement_id": "test-eng",
        })

    assert isinstance(result, PortScanOutput)
    assert result.target == "10.10.10.5"
    assert result.fast_scan is not None
    assert result.deep_scan is not None
    assert len(result.deep_scan.hosts[0].ports) == 2


@pytest.mark.asyncio
async def test_portscan_subagent_no_open_ports():
    fake_naabu = PortList(target="10.10.10.5", ports=[])
    with patch("autored.subagents.portscan.naabu_scan") as mock_naabu:
        mock_naabu.ainvoke = AsyncMock(return_value=fake_naabu)
        result = await portscan_subagent.ainvoke({
            "target": "10.10.10.5",
            "engagement_id": "test-eng",
        })
    assert result.deep_scan is None  # nmap not called when no open ports
