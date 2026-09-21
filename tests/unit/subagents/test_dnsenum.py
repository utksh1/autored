import pytest
from unittest.mock import AsyncMock, patch
from autored.subagents.dnsenum import dnsenum_subagent
from autored.tools.dnsx import DnsOutput, DnsResult, DnsRecord


@pytest.mark.asyncio
async def test_dnsenum_returns_first_result():
    fake_dns = DnsOutput(results=[DnsResult(
        hostname="lame.htb",
        records=[DnsRecord(hostname="lame.htb", record_type="A", value="10.10.10.5")],
    )])

    with patch("autored.subagents.dnsenum.dns_resolve") as mock_dns:
        mock_dns.ainvoke = AsyncMock(return_value=fake_dns)
        result = await dnsenum_subagent.ainvoke({
            "hostname": "lame.htb",
            "engagement_id": "test-eng",
        })

    assert result.hostname == "lame.htb"
    assert len(result.records) == 1
    assert result.records[0].value == "10.10.10.5"


@pytest.mark.asyncio
async def test_dnsenum_no_results():
    fake_dns = DnsOutput(results=[])
    with patch("autored.subagents.dnsenum.dns_resolve") as mock_dns:
        mock_dns.ainvoke = AsyncMock(return_value=fake_dns)
        result = await dnsenum_subagent.ainvoke({
            "hostname": "nonexistent.htb",
            "engagement_id": "test-eng",
        })
    assert result.records == []
    assert result.hostname == "nonexistent.htb"
