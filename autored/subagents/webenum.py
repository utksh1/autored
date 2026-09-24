import asyncio

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.tools.feroxbuster import feroxbuster_dir, DirResult
from autored.tools.httpx_tool import httpx_probe, HttpxResult
from autored.tools.nuclei import nuclei_scan, NucleiResult

log = get_logger("subagents.webenum")


class WebEnumOutput(BaseModel):
    url: str
    httpx_results: list[HttpxResult] = Field(default_factory=list)
    directories: list[DirResult] = Field(default_factory=list)
    nuclei_results: list[NucleiResult] = Field(default_factory=list)


@tool
async def webenum_subagent(
    url: str,
    engagement_id: str = "",
) -> WebEnumOutput:
    """Run web enumeration: httpx + feroxbuster + nuclei (web templates).

    Args:
        url: Target URL (e.g., http://10.10.10.5)
        engagement_id: Current engagement ID

    Returns:
        WebEnumOutput with httpx results, discovered directories, and nuclei findings.
    """
    log.info("webenum_start", url=url)

    # Run httpx first to confirm web service
    httpx_output = await httpx_probe.ainvoke({
        "hosts": [url],
        "engagement_id": engagement_id,
    })

    # If no web service, skip feroxbuster and nuclei
    if not httpx_output.results:
        log.info("webenum_no_web_service", url=url)
        return WebEnumOutput(url=url)

    # Run feroxbuster and nuclei in parallel
    ferox_task = feroxbuster_dir.ainvoke({
        "url": url,
        "engagement_id": engagement_id,
    })
    nuclei_task = nuclei_scan.ainvoke({
        "target": url,
        "templates": ["cves/", "vulnerabilities/", "misconfiguration/", "exposures/"],
        "engagement_id": engagement_id,
    })

    ferox_output, nuclei_output = await asyncio.gather(
        ferox_task, nuclei_task, return_exceptions=True,
    )

    # With return_exceptions=True, a failure in feroxbuster or nuclei comes
    # back as an Exception instance rather than cancelling the other. Treat
    # a failed tool as an empty result so we still surface whatever the
    # other tool found.
    def _empty_or(result, model_cls):
        if isinstance(result, Exception):
            log.warning("webenum_tool_failed", error=str(result))
            return model_cls()
        return result

    ferox_output = _empty_or(ferox_output, DirResult)
    nuclei_output = _empty_or(nuclei_output, NucleiResult)

    log.info(
        "webenum_done",
        url=url,
        dirs=len(ferox_output.results),
        nuclei_findings=len(nuclei_output.results),
    )

    return WebEnumOutput(
        url=url,
        httpx_results=httpx_output.results,
        directories=ferox_output.results,
        nuclei_results=nuclei_output.results,
    )
