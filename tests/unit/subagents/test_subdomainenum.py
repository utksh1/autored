import pytest
from unittest.mock import AsyncMock, patch
from autored.subagents.subdomainenum import subdomainenum_subagent
from autored.tools.subfinder import SubdomainList


@pytest.mark.asyncio
async def test_subdomainenum_merges_results():
    fake_subfinder = SubdomainList(domain="lame.htb",
                                   subdomains=["www.lame.htb", "ftp.lame.htb"])
    fake_amass = SubdomainList(domain="lame.htb",
                               subdomains=["ftp.lame.htb", "mail.lame.htb"])

    with patch("autored.subagents.subdomainenum.subfinder_enum") as mock_sf, \
         patch("autored.subagents.subdomainenum.amass_enum") as mock_amass:
        mock_sf.ainvoke = AsyncMock(return_value=fake_subfinder)
        mock_amass.ainvoke = AsyncMock(return_value=fake_amass)

        result = await subdomainenum_subagent.ainvoke({
            "domain": "lame.htb",
            "engagement_id": "test-eng",
        })

    # Merged: www, ftp, mail (ftp deduped)
    assert "www.lame.htb" in result.subdomains
    assert "ftp.lame.htb" in result.subdomains
    assert "mail.lame.htb" in result.subdomains
    assert len(result.subdomains) == 3  # no duplicates


@pytest.mark.asyncio
async def test_subdomainenum_both_empty():
    fake_subfinder = SubdomainList(domain="lame.htb", subdomains=[])
    fake_amass = SubdomainList(domain="lame.htb", subdomains=[])

    with patch("autored.subagents.subdomainenum.subfinder_enum") as mock_sf, \
         patch("autored.subagents.subdomainenum.amass_enum") as mock_amass:
        mock_sf.ainvoke = AsyncMock(return_value=fake_subfinder)
        mock_amass.ainvoke = AsyncMock(return_value=fake_amass)

        result = await subdomainenum_subagent.ainvoke({
            "domain": "lame.htb",
            "engagement_id": "test-eng",
        })

    assert result.subdomains == []
    assert result.domain == "lame.htb"
