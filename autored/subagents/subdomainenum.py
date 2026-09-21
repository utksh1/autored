import asyncio

from langchain_core.tools import tool

from autored.logging import get_logger
from autored.tools.amass import amass_enum
from autored.tools.subfinder import subfinder_enum, SubdomainList

log = get_logger("subagents.subdomainenum")


@tool
async def subdomainenum_subagent(
    domain: str,
    engagement_id: str = "",
) -> SubdomainList:
    """Run subdomain enumeration: subfinder + amass in parallel, merge results.

    Args:
        domain: Root domain (e.g., "example.com")
        engagement_id: Current engagement ID

    Returns:
        SubdomainList with merged, deduplicated subdomains.
    """
    log.info("subdomainenum_start", domain=domain)

    # Run both in parallel
    subfinder_task = subfinder_enum.ainvoke({
        "domain": domain,
        "engagement_id": engagement_id,
    })
    amass_task = amass_enum.ainvoke({
        "domain": domain,
        "engagement_id": engagement_id,
    })

    subfinder_result, amass_result = await asyncio.gather(subfinder_task, amass_task)

    # Merge and dedupe (preserve first-seen order)
    all_subs = subfinder_result.subdomains + amass_result.subdomains
    seen: set[str] = set()
    unique: list[str] = []
    for s in all_subs:
        if s not in seen:
            seen.add(s)
            unique.append(s)

    all_sources = list(set(subfinder_result.sources + amass_result.sources))

    log.info("subdomainenum_done", domain=domain, total=len(unique))

    return SubdomainList(
        domain=domain,
        subdomains=unique,
        sources=all_sources,
    )
