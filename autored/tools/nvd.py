"""AutoRed NVD query tool — Phase 2, Task 4.

Wraps the NVD 2.0 REST API (``services.nvd.nist.gov/rest/json/cves/2.0``)
with an async httpx client, retries with exponential backoff on 5xx/429,
and a Pydantic-parsed ``list[NvdCve]`` result.

Decorator order note (Ruling 1 in the Phase 1 SDD ledger): ``@tool`` is
applied OUTERMOST and ``@roe_guard`` INNER. The brief spec'd the opposite
order (``@roe_guard`` over ``@tool``), but that produces a
StructuredTool that is not callable via ``.ainvoke({...})`` at runtime
(see Batch A review of nmap/nuclei/httpx wrappers). Same pattern as every
other Phase 1 tool wrapper.

Return-type note: the brief's "Interfaces" line spec'd
``nvd_query(...) -> NvdResult``, but the brief's own Step 4 code returns
``list[NvdCve]``. We follow the Step 4 code (``list[NvdCve]``) and keep
``NvdResult`` defined for callers that want to wrap the list themselves.

URL-builder note: the brief's ``_build_nvd_url`` used ``keywordSearch``,
but the brief's ``test_build_nvd_url`` asserts ``"cpeName" in url`` — so
we use ``cpeName`` (proper CPE 2.3 form, URL-encoded) to match both the
test and the brief's docstring ("CPE name filter").
"""

from __future__ import annotations

import urllib.parse

import httpx
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.retry import with_retry
from autored.roe_guard import roe_guard

log = get_logger("tools.nvd")

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdCve(BaseModel):
    """One CVE row parsed from the NVD 2.0 ``vulnerabilities[]`` array."""

    cve_id: str
    description: str
    cvss_score: float | None = None
    severity: str | None = None
    references: list[str] = Field(default_factory=list)


class NvdResult(BaseModel):
    """Optional wrapper for callers that want product+version bundled with
    the parsed CVE list. ``nvd_query`` returns ``list[NvdCve]`` directly;
    this model exists for agents that want to re-wrap the result.
    """

    product: str
    version: str
    cves: list[NvdCve] = Field(default_factory=list)
    raw_response_path: str = ""


def _build_nvd_url(product: str, version: str) -> str:
    """Build NVD API URL with CPE name filter.

    CPE 2.3 format: ``cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*``.
    NVD accepts the ``cpeName`` query parameter as a URL-encoded CPE string
    and supports partial matches (vendor wildcard ``*``).

    The product and version are not URL-encoded (they're safe alphanumerics
    in practice); the CPE structural characters (``:`` and ``*``) are
    percent-encoded via ``urllib.parse.quote(safe='')`` so the request is
    well-formed per RFC 3986 / NVD API spec.
    """
    cpe = f"cpe:2.3:a:*:{product}:{version}:*:*:*:*:*:*:*"
    encoded_cpe = urllib.parse.quote(cpe, safe="")
    return f"{NVD_API_BASE}?cpeName={encoded_cpe}&resultsPerPage=20"


def _parse_nvd_response(data: dict) -> list[NvdCve]:
    """Parse NVD 2.0 JSON response into a list of ``NvdCve``.

    Walks ``data["vulnerabilities"]``, extracts the English description
    from ``cve.descriptions[]``, picks the first available CVSS metric
    block (V30 → V31 → V2 fallback), and pulls reference URLs.

    Returns an empty list if ``vulnerabilities`` is missing or empty.
    Never raises — malformed entries are skipped (logged at warning).
    """
    cves: list[NvdCve] = []
    for vuln in data.get("vulnerabilities", []):
        try:
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")
            if not cve_id:
                continue
            descriptions = cve_data.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "",
            )
            # Extract CVSS v3 score (prefer V30, fallback to V31, then V2).
            cvss_score: float | None = None
            severity: str | None = None
            cvss_metrics = (
                cve_data.get("cvssMetricV30", [])
                or cve_data.get("cvssMetricV31", [])
                or cve_data.get("cvssMetricV2", [])
            )
            if cvss_metrics:
                cvss_data = cvss_metrics[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity")
            references = [r["url"] for r in cve_data.get("references", []) if "url" in r]
            cves.append(
                NvdCve(
                    cve_id=cve_id,
                    description=description,
                    cvss_score=cvss_score,
                    severity=severity,
                    references=references,
                )
            )
        except (KeyError, TypeError) as e:
            log.warning(
                "nvd_parse_entry_failed",
                cve_id=cve_data.get("id", "<unknown>"),
                error=str(e),
            )
    return cves


@tool
@roe_guard(allowed_categories=["cve_query", "read_only"])
async def nvd_query(
    product: str,
    version: str,
    engagement_id: str = "",
) -> list[NvdCve]:
    """Query NVD (National Vulnerability Database) for CVEs matching a
    product+version.

    Args:
        product: Product name (e.g., "nginx", "apache", "openssh")
        version: Version string (e.g., "1.17.3", "2.2.22")
        engagement_id: Current engagement ID

    Returns:
        List of NvdCve objects. Empty list if NVD is unreachable or no
        matches — never raises to the caller.
    """
    url = _build_nvd_url(product, version)
    log.info("nvd_query_start", product=product, version=version, url=url)

    @with_retry(max_attempts=3, base_delay=2.0)
    async def _fetch() -> dict:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(url, headers={"apiKey": ""})
            if response.status_code >= 500:
                log.warning("nvd_5xx", status=response.status_code, url=url)
                raise RuntimeError(f"NVD returned {response.status_code}")
            if response.status_code == 429:
                log.warning("nvd_rate_limited", url=url)
                raise RuntimeError("NVD rate limit (429)")
            response.raise_for_status()
            return response.json()

    try:
        data = await _fetch()
        cves = _parse_nvd_response(data)
        log.info("nvd_query_done", product=product, cves_found=len(cves))
        return cves
    except Exception as e:
        # Always return empty list on failure, never crash. The RoE guard,
        # the retry decorator, and this outer try/except form a 3-layer
        # defence: any unexpected error (network, JSON parse, retry
        # exhausted) collapses to an empty CVE list so the calling agent
        # can keep moving.
        log.error("nvd_query_failed", product=product, error=str(e), url=url)
        return []
