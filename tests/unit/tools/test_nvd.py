r"""Tests for the nvd tool wrapper (Phase 2, Task 4).

Uses ``pytest-httpx`` (already a dev dep since Phase 0) to mock the NVD 2.0
API. The brief shows ``url=lambda u: "services.nvd.nist.gov" in u`` for
the URL matcher, but ``pytest-httpx==0.35.0``'s ``_url_match`` only accepts
``str | re.Pattern | httpx.URL`` (NOT a callable) — a callable URL matcher
fails with ``AttributeError: 'function' object has no attribute 'params'``
inside ``_url_match`` when it tries ``dict(url_to_match.params)`` on the
lambda. We use ``url=re.compile(r".*services\.nvd\.nist\.gov.*")`` instead:
``re.Pattern`` is the only fuzzy-match form pytest-httpx supports, and
``_url_match`` calls ``.match(str(received))`` on it (anchored at start, so
the leading ``.*`` lets the substring match anywhere in the URL).
"""

import json
import re

import pytest

from autored.config import load_roe
from autored.roe_guard import register_roe
from autored.tools.nvd import (
    NvdCve,
    NvdResult,
    _build_nvd_url,
    _parse_nvd_response,
    nvd_query,
)


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
    data = json.loads(empty_response)
    result = _parse_nvd_response(data)
    assert result == []


@pytest.mark.asyncio
async def test_nvd_query_success(httpx_mock, nginx_response, sandbox_roe_yaml):
    """Call nvd_query via .ainvoke with a mocked 200 response from NVD.

    RoE registration is required because the @roe_guard decorator blocks any
    tool call without a registered engagement (even read-only / cve_query
    ones) — the brief omitted this setup, so we register a sandbox RoE for
    the test engagement.
    """
    roe = load_roe(sandbox_roe_yaml)
    register_roe("nvd-test", roe)

    httpx_mock.add_response(
        url=re.compile(r".*services\.nvd\.nist\.gov.*"),
        text=nginx_response,
    )
    result = await nvd_query.ainvoke(
        {
            "product": "nginx",
            "version": "1.17.3",
            "engagement_id": "nvd-test",
        }
    )
    assert isinstance(result, list)
    assert len(result) >= 1
    assert isinstance(result[0], NvdCve)
    assert result[0].cve_id == "CVE-2017-7529"


@pytest.mark.asyncio
async def test_nvd_query_5xx_returns_empty(httpx_mock, sandbox_roe_yaml):
    """Review Focus: NVD returns 5xx — tool retries, then returns empty list.

    3 mock 503 responses for 3 retry attempts (``with_retry(max_attempts=3)``).
    After 3 failures, the retry decorator re-raises; the outer ``except`` in
    ``nvd_query`` catches and returns ``[]`` — never raises to the caller.
    """
    roe = load_roe(sandbox_roe_yaml)
    register_roe("nvd-test", roe)

    nvd_url_matcher = re.compile(r".*services\.nvd\.nist\.gov.*")
    for _ in range(3):
        httpx_mock.add_response(
            url=nvd_url_matcher,
            status_code=503,
        )
    # After 3 retries, tool should return empty list, not raise
    result = await nvd_query.ainvoke(
        {
            "product": "nginx",
            "version": "1.17.3",
            "engagement_id": "nvd-test",
        }
    )
    assert result == []


@pytest.mark.asyncio
async def test_nvd_query_ainvoke_works_with_roe_guard(httpx_mock, nginx_response, sandbox_roe_yaml):
    """Integration test: call the decorated tool end-to-end via .ainvoke().

    Regression catcher for the decorator-stacking bug (Ruling 1 in the Phase
    1 SDD ledger): ``@tool`` must be applied OUTERMOST and ``@roe_guard``
    INNER. The brief spec'd the opposite order (``@roe_guard`` over ``@tool``),
    which produces a StructuredTool that is not callable via
    ``.ainvoke({...})`` (``TypeError: 'StructuredTool' object is not
    callable``). With the swapped order, the StructuredTool's underlying
    coroutine is a regular async def, and ``.ainvoke({...})`` dispatches
    correctly through the RoE wrapper.
    """
    # 1. Register a RoE for the test engagement.
    roe = load_roe(sandbox_roe_yaml)
    register_roe("nvd-int", roe)

    # 2. Mock the NVD 2.0 API to return the nginx fixture.
    httpx_mock.add_response(
        url=re.compile(r".*services\.nvd\.nist\.gov.*"),
        text=nginx_response,
    )

    # 3. Call the tool via .ainvoke({...}) — the only correct way to call a
    #    StructuredTool.
    result = await nvd_query.ainvoke(
        {
            "product": "nginx",
            "version": "1.17.3",
            "engagement_id": "nvd-int",
        }
    )

    # 4. Assert the returned object is a list of NvdCve with the expected
    #    fields populated from the fixture.
    assert isinstance(result, list)
    assert len(result) == 1
    cve = result[0]
    assert isinstance(cve, NvdCve)
    assert cve.cve_id == "CVE-2017-7529"
    assert cve.cvss_score == 7.5
    assert cve.severity == "HIGH"
    assert "Nginx range filter" in cve.description
    assert cve.references == ["https://nvd.nist.gov/vuln/detail/CVE-2017-7529"]


def test_nvd_result_model_importable():
    """Sanity-check NvdResult is defined (brief Step 4 defines it even though
    nvd_query returns ``list[NvdCve]``, not ``NvdResult``).
    """
    r = NvdResult(product="nginx", version="1.17.3")
    assert r.product == "nginx"
    assert r.cves == []
    assert r.raw_response_path == ""
