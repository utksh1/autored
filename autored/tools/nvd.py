"""NVD (National Vulnerability Database) query tool.

Wraps the NIST NVD 2.0 REST API. Used by the Vuln Agent (Phase 2) to look up
CVEs matching a product+version pair. HTTP failures (5xx, 429, network) are
retried with exponential backoff via ``with_retry``; if all retries are
exhausted the tool returns an empty list rather than raising — the Vuln
Agent treats "no CVEs found" and "NVD unreachable" identically so the
pipeline never crashes on a flaky external dependency.
"""
import httpx
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.roe_guard import roe_guard
from autored.retry import with_retry

log = get_logger("tools.nvd")

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdCve(BaseModel):
    cve_id: str
    description: str
    cvss_score: float | None = None
    severity: str | None = None
    references: list[str] = Field(default_factory=list)


class NvdResult(BaseModel):
    product: str
    version: str
    cves: list[NvdCve] = Field(default_factory=list)
    raw_response_path: str = ""


def _build_nvd_url(product: str, version: str) -> str:
    """Build NVD API URL with CPE name filter.

    CPE 2.3 format: ``cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*``
    We don't know the vendor at query time, so we use ``*`` (wildcard) —
    NVD's ``cpeName`` parameter accepts partial CPE matches with wildcards.
    """
    cpe = f"cpe:2.3:a:*:{product}:{version}:*:*:*:*:*:*:*"
    return f"{NVD_API_BASE}?cpeName={cpe}&resultsPerPage=20"


def _parse_nvd_response(data: dict) -> list[NvdCve]:
    cves = []
    for vuln in data.get("vulnerabilities", []):
        cve_data = vuln.get("cve", {})
        cve_id = cve_data.get("id", "")
        descriptions = cve_data.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "",
        )
        # Extract CVSS v3 score (prefer v3.1, then v3.0, then fall back to v2)
        cvss_score = None
        severity = None
        cvss_metrics = (
            cve_data.get("cvssMetricV31", [])
            or cve_data.get("cvssMetricV30", [])
            or cve_data.get("cvssMetricV2", [])
        )
        if cvss_metrics:
            cvss_data = cvss_metrics[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity")
        references = [
            r["url"] for r in cve_data.get("references", []) if "url" in r
        ]
        cves.append(
            NvdCve(
                cve_id=cve_id,
                description=description,
                cvss_score=cvss_score,
                severity=severity,
                references=references,
            )
        )
    return cves


@tool
@roe_guard(allowed_categories=["cve_query", "read_only"])
async def nvd_query(
    product: str,
    version: str,
    engagement_id: str = "",
) -> list[NvdCve]:
    """Query NVD (National Vulnerability Database) for CVEs matching a product+version.

    Args:
        product: Product name (e.g., "nginx", "apache", "openssh")
        version: Version string (e.g., "1.17.3", "2.2.22")
        engagement_id: Current engagement ID

    Returns:
        List of NvdCve objects. Empty list if NVD is unreachable or no matches.
    """
    url = _build_nvd_url(product, version)
    log.info("nvd_query_start", product=product, version=version)

    @with_retry(max_attempts=3, base_delay=2.0)
    async def _fetch():
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(url, headers={"apiKey": ""})  # NVD API key optional
            if response.status_code >= 500:
                log.warning("nvd_5xx", status=response.status_code)
                raise RuntimeError(f"NVD returned {response.status_code}")
            if response.status_code == 429:
                log.warning("nvd_rate_limited")
                raise RuntimeError("NVD rate limit (429)")
            response.raise_for_status()
            return response.json()

    try:
        data = await _fetch()
        cves = _parse_nvd_response(data)
        log.info("nvd_query_done", product=product, cves_found=len(cves))
        return cves
    except Exception as e:
        log.error("nvd_query_failed", product=product, error=str(e))
        return []  # always return empty list on failure, never crash
