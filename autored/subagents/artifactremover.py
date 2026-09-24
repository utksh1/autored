"""ArtifactRemover sub-agent (spec §7.4, Phase 5).

Executes every artifact's ``removal_command`` **verbatim** (spec §6.4:
"Every persistence action creates a PersistenceArtifact with the exact
removal command. Cleanup Agent runs these verbatim.") on the artifact's
host, transported per the host plan (impacket-wmiexec for Windows /
ssh for Linux) and authenticated with the engagement credentials
recorded in the host plan.

A failed removal is recorded with the error and ``verified=False`` —
the VerificationScanner only flips ``verified`` after an absence proof
(Review Focus #5).
"""
from datetime import datetime

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.models.cleanup import CleanupResult
from autored.tools.cleanup import cleanup_execute

log = get_logger("subagents.artifactremover")


class ArtifactRemoverOutput(BaseModel):
    """Removal outcomes for one host's artifacts."""

    results: list[CleanupResult] = Field(default_factory=list)


@tool
async def artifactremover_subagent(
    host_plan: dict,
    artifacts: list[dict],
    engagement_id: str = "",
) -> ArtifactRemoverOutput:
    """Execute removal commands for one host's artifacts.

    Args:
        host_plan: A HostCleanupPlan.model_dump() — carries transport,
            username, password, nthash for the host.
        artifacts: PersistenceArtifact.model_dump() dicts for this host.
        engagement_id: Current engagement ID.

    Returns:
        ArtifactRemoverOutput with one CleanupResult per artifact
        (``verified`` is always False here — verification is the
        VerificationScanner's job).
    """
    host_ip = host_plan.get("host_ip", "unknown")
    log.info("artifactremover_start", host_ip=host_ip, count=len(artifacts))
    results: list[CleanupResult] = []
    for artifact in artifacts:
        removal = await cleanup_execute.ainvoke(
            host_ip=artifact["host_ip"],
            removal_command=artifact["removal_command"],
            transport=host_plan.get("transport", "impacket_wmiexec"),
            username=host_plan.get("username", ""),
            password=host_plan.get("password", ""),
            nthash=host_plan.get("nthash", ""),
            engagement_id=engagement_id,
        )
        results.append(CleanupResult(
            artifact_id=artifact["id"],
            host_ip=artifact["host_ip"],
            removal_command=artifact["removal_command"],
            success=removal.success,
            verified=False,  # verification is the scanner's job
            error=removal.error,
            timestamp=datetime.utcnow(),
        ))
        log.info(
            "artifactremover_item", host_ip=artifact["host_ip"],
            artifact_id=artifact["id"], success=removal.success,
        )
    log.info("artifactremover_done", host_ip=host_ip, removed=len(results))
    return ArtifactRemoverOutput(results=results)
