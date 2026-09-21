import asyncio
from pydantic import BaseModel, Field
from langchain_core.tools import tool
from autored.tools.nvd import nvd_query, NvdCve
from autored.models.service import Service
from autored.logging import get_logger

log = get_logger("subagents.cvematcher")

class CveMatch(BaseModel):
    service: str
    host_ip: str
    port: int
    product: str
    version: str
    cves: list[NvdCve] = Field(default_factory=list)

class CVEMatcherOutput(BaseModel):
    cve_matches: list[CveMatch] = Field(default_factory=list)

@tool
async def cvematcher_subagent(
    services: list[dict],
    engagement_id: str = "",
) -> CVEMatcherOutput:
    """Query NVD for CVEs matching each service's product+version.

    Args:
        services: List of Service dicts (host_ip, port, service, product, version)
        engagement_id: Current engagement ID

    Returns:
        CVEMatcherOutput with CVE matches per service.
    """
    log.info("cvematcher_start", services_count=len(services))

    # Filter to services with product+version info
    queryable = [
        s for s in services
        if s.get("product") and s.get("version")
    ]
    log.info("cvematcher_queryable", count=len(queryable))

    # Query NVD in parallel for each queryable service
    async def query_one(service_dict: dict) -> CveMatch:
        product = service_dict["product"]
        version = service_dict["version"]
        cves = await nvd_query.ainvoke({
            "product": product,
            "version": version,
            "engagement_id": engagement_id,
        })
        return CveMatch(
            service=service_dict.get("service", ""),
            host_ip=service_dict["host_ip"],
            port=service_dict["port"],
            product=product,
            version=version,
            cves=cves,
        )

    matches = await asyncio.gather(*[query_one(s) for s in queryable])

    # Only keep services that actually yielded at least one CVE — a service
    # with no CVE matches carries no actionable signal for the downstream
    # Vuln Agent, so we drop it here. This also makes NVD outages (which
    # surface as empty lists from nvd_query) indistinguishable from
    # "no known CVEs", which is the desired graceful-degradation behaviour.
    matched = [m for m in matches if m.cves]

    log.info("cvematcher_done", matches=len(matched))
    return CVEMatcherOutput(cve_matches=matched)
