from langchain_core.tools import tool

from autored.logging import get_logger
from autored.tools.sqlmap import sqlmap_run, SqlmapResult

log = get_logger("subagents.sqliagent")


@tool
async def sqliagent_subagent(
    url: str,
    options: list[str] | None = None,
    engagement_id: str = "",
) -> SqlmapResult:
    """Run SQL injection testing via sqlmap.

    Args:
        url: Target URL with parameters
        options: Additional sqlmap options
        engagement_id: Current engagement ID

    Returns:
        SqlmapResult with vulnerability status and injection points.
    """
    log.info("sqliagent_start", url=url)
    result = await sqlmap_run.ainvoke({
        "url": url,
        "options": options,
        "engagement_id": engagement_id,
    })
    log.info("sqliagent_done", url=url, vulnerable=result.vulnerable)
    return result
