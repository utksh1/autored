# tests/unit/subagents/test_cvematcher.py
import pytest
from unittest.mock import AsyncMock, patch
from autored.subagents.cvematcher import cvematcher_subagent, CVEMatcherOutput
from autored.models.service import Service
from autored.tools.nvd import NvdCve

@pytest.mark.asyncio
async def test_cvematcher_queries_nvd_for_each_service():
    services = [
        Service(host_ip="10.10.10.5", port=80, protocol="tcp", service="http", product="nginx", version="1.17.3"),
        Service(host_ip="10.10.10.5", port=22, protocol="tcp", service="ssh", product="OpenSSH", version="4.7p1"),
    ]
    fake_cves = [NvdCve(cve_id="CVE-2017-7529", description="nginx overflow", cvss_score=7.5, severity="HIGH")]

    with patch("autored.subagents.cvematcher.nvd_query") as mock_nvd:
        mock_nvd.ainvoke = AsyncMock(return_value=fake_cves)
        result = await cvematcher_subagent.ainvoke({
            "services": [s.model_dump() for s in services],
            "engagement_id": "test-eng",
        })

    assert isinstance(result, CVEMatcherOutput)
    # Should have called nvd_query for each service with a product+version
    assert mock_nvd.ainvoke.call_count == 2
    assert len(result.cve_matches) >= 1

@pytest.mark.asyncio
async def test_cvematcher_skips_services_without_version():
    services = [
        Service(host_ip="10.10.10.5", port=80, protocol="tcp", service="http", product=None, version=None),
    ]
    with patch("autored.subagents.cvematcher.nvd_query") as mock_nvd:
        mock_nvd.ainvoke = AsyncMock(return_value=[])
        result = await cvematcher_subagent.ainvoke({
            "services": [s.model_dump() for s in services],
            "engagement_id": "test-eng",
        })
    # Should not query NVD for services without version info
    mock_nvd.ainvoke.assert_not_called()
    assert result.cve_matches == []

@pytest.mark.asyncio
async def test_cvematcher_handles_nvd_failures_gracefully():
    services = [
        Service(host_ip="10.10.10.5", port=80, protocol="tcp", service="http", product="nginx", version="1.17.3"),
    ]
    with patch("autored.subagents.cvematcher.nvd_query") as mock_nvd:
        # nvd_query already returns [] on failure (Task 4), so we test that empty results don't break us
        mock_nvd.ainvoke = AsyncMock(return_value=[])
        result = await cvematcher_subagent.ainvoke({
            "services": [s.model_dump() for s in services],
            "engagement_id": "test-eng",
        })
    assert result.cve_matches == []
