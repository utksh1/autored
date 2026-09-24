"""Tests for the CVEMatcher sub-agent (Phase 2, Task 6).

Verifies that ``cvematcher_subagent`` queries NVD in parallel for each service
with product+version info, skips services without version info, and degrades
gracefully when NVD returns empty or raises (Phase 0 T9 fix:
``asyncio.gather(..., return_exceptions=True)`` so a single failing query
doesn't cancel the whole batch).
"""

from unittest.mock import AsyncMock, patch

import pytest

from autored.models.service import Service
from autored.subagents.cvematcher import (
    CveMatch,
    CVEMatcherOutput,
    cvematcher_subagent,
)
from autored.tools.nvd import NvdCve


@pytest.mark.asyncio
async def test_cvematcher_queries_nvd_for_each_service():
    """Two queryable services → NVD is called twice (in parallel)."""
    services = [
        Service(
            host_ip="10.10.10.5",
            port=80,
            protocol="tcp",
            service="http",
            product="nginx",
            version="1.17.3",
        ),
        Service(
            host_ip="10.10.10.5",
            port=22,
            protocol="tcp",
            service="ssh",
            product="OpenSSH",
            version="4.7p1",
        ),
    ]
    fake_cves = [
        NvdCve(
            cve_id="CVE-2017-7529",
            description="nginx overflow",
            cvss_score=7.5,
            severity="HIGH",
        )
    ]

    with patch("autored.subagents.cvematcher.nvd_query") as mock_nvd:
        mock_nvd.ainvoke = AsyncMock(return_value=fake_cves)
        result = await cvematcher_subagent.ainvoke(
            {
                "services": [s.model_dump() for s in services],
                "engagement_id": "test-eng",
            }
        )

    assert isinstance(result, CVEMatcherOutput)
    # Should have called nvd_query for each service with a product+version
    assert mock_nvd.ainvoke.call_count == 2
    assert len(result.cve_matches) >= 1
    # Each CveMatch should carry the CVE list and service metadata
    for m in result.cve_matches:
        assert isinstance(m, CveMatch)
        assert len(m.cves) == 1
        assert m.cves[0].cve_id == "CVE-2017-7529"
        assert m.host_ip == "10.10.10.5"
        assert m.port in (80, 22)


@pytest.mark.asyncio
async def test_cvematcher_skips_services_without_version():
    """Services without product/version are filtered out — NVD is not called."""
    services = [
        Service(
            host_ip="10.10.10.5",
            port=80,
            protocol="tcp",
            service="http",
            product=None,
            version=None,
        ),
    ]
    with patch("autored.subagents.cvematcher.nvd_query") as mock_nvd:
        mock_nvd.ainvoke = AsyncMock(return_value=[])
        result = await cvematcher_subagent.ainvoke(
            {
                "services": [s.model_dump() for s in services],
                "engagement_id": "test-eng",
            }
        )
    # Should not query NVD for services without version info
    mock_nvd.ainvoke.assert_not_called()
    assert result.cve_matches == []


@pytest.mark.asyncio
async def test_cvematcher_handles_nvd_failures_gracefully():
    """NVD returns empty list (Task 4 graceful failure) — sub-agent returns []."""
    services = [
        Service(
            host_ip="10.10.10.5",
            port=80,
            protocol="tcp",
            service="http",
            product="nginx",
            version="1.17.3",
        ),
    ]
    with patch("autored.subagents.cvematcher.nvd_query") as mock_nvd:
        # nvd_query already returns [] on failure (Task 4), so we test that
        # empty results don't break us
        mock_nvd.ainvoke = AsyncMock(return_value=[])
        result = await cvematcher_subagent.ainvoke(
            {
                "services": [s.model_dump() for s in services],
                "engagement_id": "test-eng",
            }
        )
    assert result.cve_matches == []


@pytest.mark.asyncio
async def test_cvematcher_isolates_per_service_exceptions():
    """Review Focus (Phase 0 T9 fix): a raised exception on one service's NVD
    query must NOT crash the whole batch — ``asyncio.gather(...,
    return_exceptions=True)`` turns the raised exception into an Exception
    instance in the result list, and the sub-agent filters those out.

    Without this fix (plain ``asyncio.gather(*tasks)``), a single failing
    NVD query would propagate the exception and cancel the other in-flight
    queries, losing all CVE matches for the engagement.
    """
    services = [
        Service(
            host_ip="10.10.10.5",
            port=80,
            protocol="tcp",
            service="http",
            product="nginx",
            version="1.17.3",
        ),
        Service(
            host_ip="10.10.10.5",
            port=22,
            protocol="tcp",
            service="ssh",
            product="OpenSSH",
            version="4.7p1",
        ),
    ]
    fake_cves_ssh = [
        NvdCve(cve_id="CVE-2018-15473", description="openssh user enum", cvss_score=5.3)
    ]

    with patch("autored.subagents.cvematcher.nvd_query") as mock_nvd:
        # First call raises; second call returns CVEs. asyncio.gather with
        # return_exceptions=True captures the exception without cancelling
        # the second call.
        mock_nvd.ainvoke = AsyncMock(
            side_effect=[RuntimeError("simulated NVD outage"), fake_cves_ssh]
        )
        result = await cvematcher_subagent.ainvoke(
            {
                "services": [s.model_dump() for s in services],
                "engagement_id": "test-eng",
            }
        )

    assert isinstance(result, CVEMatcherOutput)
    # The failing service is dropped; the surviving service's matches are kept.
    assert len(result.cve_matches) == 1
    assert result.cve_matches[0].product == "OpenSSH"
    assert result.cve_matches[0].cves[0].cve_id == "CVE-2018-15473"
