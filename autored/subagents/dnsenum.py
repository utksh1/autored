from langchain_core.tools import tool

from autored.logging import get_logger
from autored.tools.dnsx import dns_resolve, DnsResult

log = get_logger("subagents.dnsenum")


@tool
async def dnsenum_subagent(
    hostname: str,
    engagement_id: str = "",
) -> DnsResult:
    """Resolve DNS records for a single hostname.

    Args:
        hostname: Hostname to resolve
        engagement_id: Current engagement ID

    Returns:
        DnsResult with all records for the hostname. Empty records list if not found.
    """
    log.info("dnsenum_start", hostname=hostname)

    output = await dns_resolve.ainvoke({
        "hostnames": [hostname],
        "engagement_id": engagement_id,
    })

    # dns_resolve returns DnsOutput with list of DnsResult; take first match or empty
    for result in output.results:
        if result.hostname == hostname:
            log.info("dnsenum_done", hostname=hostname, records=len(result.records))
            return result

    log.info("dnsenum_no_results", hostname=hostname)
    return DnsResult(hostname=hostname, records=[])
