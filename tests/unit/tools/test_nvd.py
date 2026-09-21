# tests/unit/tools/test_nvd.py
import re
import pytest
import httpx
from pathlib import Path
from autored.tools.nvd import _build_nvd_url, _parse_nvd_response, NvdResult

# pytest-httpx 0.35.0 dropped callable URL matchers (the plan's
# `url=lambda u: ...` form raises ``'function' object has no attribute
# 'params'`` because ``_url_match`` accesses ``url_to_match.params``).
# Use a regex pattern (anchored at start via ``re.match``) instead.
_NVD_URL_RE = re.compile(r"https?://services\.nvd\.nist\.gov.*")


@pytest.fixture(autouse=True)
def _register_test_roe():
    """Register a permissive RoE for engagement_id='test'.

    The plan's test calls ``nvd_query.ainvoke({..., "engagement_id": "test"})``
    but does not register RoE for "test". The Phase 1 ``roe_guard`` decorator
    (added in Phase 1 Task 9) raises ``RoEViolation`` when no RoE is registered
    for the engagement. Without this fixture, every ``nvd_query.ainvoke`` call
    would raise before reaching the HTTP layer. We register a permissive
    sandbox RoE (0.0.0.0/0, all techniques allowed) so the roe_guard audit
    check passes and the test can exercise the actual HTTP + retry logic.
    Cleaned up after each test to avoid leaking state into the global
    ``_roe_registry``.
    """
    from autored.roe_guard import register_roe, _roe_registry
    from autored.models.roe import RulesOfEngagement

    saved = _roe_registry.get("test")
    roe = RulesOfEngagement(
        engagement_name="t", operator="o", operator_signature="s",
        allowed_ips=["0.0.0.0/0"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, kernel_exploits_allowed=True,
        hitl_mode="auto_approve",
    )
    register_roe("test", roe)
    try:
        yield
    finally:
        if saved is None:
            _roe_registry.pop("test", None)
        else:
            _roe_registry["test"] = saved


@pytest.fixture
def nginx_response(fixtures_dir):
    return (fixtures_dir / "nvd_response_nginx.json").read_text()


@pytest.fixture
def empty_response(fixtures_dir):
    return (fixtures_dir / "nvd_response_empty.json").read_text()


def test_build_nvd_url():
    url = _build_nvd_url("nginx", "1.17.3")
    assert "services.nvd.nist.gov" in url
    assert "cves/2.0" in url
    assert "cpeName" in url
    assert "nginx" in url
    assert "1.17.3" in url


def test_parse_nvd_response(nginx_response):
    import json
    data = json.loads(nginx_response)
    result = _parse_nvd_response(data)
    assert isinstance(result, list)
    assert len(result) == 1
    cve = result[0]
    assert cve.cve_id == "CVE-2017-7529"
    assert cve.cvss_score == 7.5
    assert cve.severity == "HIGH"
    assert "Nginx range filter" in cve.description


def test_parse_nvd_empty(empty_response):
    import json
    data = json.loads(empty_response)
    result = _parse_nvd_response(data)
    assert result == []


@pytest.mark.asyncio
async def test_nvd_query_success(httpx_mock, nginx_response):
    from autored.tools.nvd import nvd_query
    httpx_mock.add_response(
        url=_NVD_URL_RE,
        text=nginx_response,
    )
    result = await nvd_query.ainvoke({
        "product": "nginx",
        "version": "1.17.3",
        "engagement_id": "test",
    })
    assert isinstance(result, list)
    assert len(result) >= 1
    assert result[0].cve_id == "CVE-2017-7529"


@pytest.mark.asyncio
async def test_nvd_query_5xx_returns_empty(httpx_mock, empty_response):
    """Review Focus: NVD returns 5xx — tool retries, then returns empty list."""
    from autored.tools.nvd import nvd_query
    httpx_mock.add_response(url=_NVD_URL_RE, status_code=503)
    httpx_mock.add_response(url=_NVD_URL_RE, status_code=503)
    httpx_mock.add_response(url=_NVD_URL_RE, status_code=503)
    # After 3 retries, tool should return empty list, not raise
    result = await nvd_query.ainvoke({
        "product": "nginx",
        "version": "1.17.3",
        "engagement_id": "test",
    })
    assert result == []
