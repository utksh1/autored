from langchain_core.tools import tool

from autored.logging import get_logger
from autored.tools.gobuster_vhost import gobuster_vhost, VhostList

log = get_logger("subagents.vhostenum")


@tool
async def vhostenum_subagent(
    url: str,
    engagement_id: str = "",
) -> VhostList:
    """Run virtual host enumeration via gobuster vhost.

    Args:
        url: Target URL (e.g., http://lame.htb)
        engagement_id: Current engagement ID

    Returns:
        VhostList with discovered virtual hosts.
    """
    log.info("vhostenum_start", url=url)
    result = await gobuster_vhost.ainvoke({
        "url": url,
        "engagement_id": engagement_id,
    })
    log.info("vhostenum_done", url=url, vhosts=len(result.vhosts))
    return result
