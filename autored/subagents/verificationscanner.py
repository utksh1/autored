"""VerificationScanner sub-agent (spec §7.4, Phase 5).

The "re-scan to verify artifacts removed" half of the Phase 5 ship
criteria (spec §13.5: "Cleanup Agent successfully removes all
artifacts (verifiable via re-scan) / No artifacts remain after
cleanup"). Per artifact: build the method-specific verify command
(Task 5's ``_build_verify_command``), run it through the same
transport, parse for absence. The result CleanupResult records
``verified`` — with ``error`` set when the artifact is still present
(Review Focus #5).
"""
from datetime import datetime

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.models.cleanup import CleanupResult
from autored.tools.cleanup import _build_verify_command, cleanup_verify

log = get_logger("subagents.verificationscanner")


class VerificationScannerOutput(BaseModel):
    """Verification outcomes for one host's artifacts."""

    results: list[CleanupResult] = Field(default_factory=list)


@tool
async def verificationscanner_subagent(
    host_plan: dict,
    artifacts: list[dict],
    engagement_id: str = "",
) -> VerificationScannerOutput:
    """Re-scan a host to verify its artifacts were removed.

    Args:
        host_plan: A HostCleanupPlan.model_dump() — transport + creds.
        artifacts: PersistenceArtifact.model_dump() dicts for this host.
        engagement_id: Current engagement ID.

    Returns:
        VerificationScannerOutput with one CleanupResult per artifact;
        ``verified`` is True only on proven absence.
    """
    host_ip = host_plan.get("host_ip", "unknown")
    log.info("verificationscanner_start", host_ip=host_ip, count=len(artifacts))
    results: list[CleanupResult] = []
    for artifact in artifacts:
        verify_cmd = _build_verify_command(artifact["method"], artifact.get("details") or {})
        scan = await cleanup_verify.ainvoke(
            host_ip=artifact["host_ip"],
            verify_command=verify_cmd,
            method=artifact["method"],
            transport=host_plan.get("transport", "impacket_wmiexec"),
            username=host_plan.get("username", ""),
            password=host_plan.get("password", ""),
            nthash=host_plan.get("nthash", ""),
            engagement_id=engagement_id,
        )
        results.append(CleanupResult(
            artifact_id=artifact["id"],
            host_ip=artifact["host_ip"],
            removal_command=verify_cmd,
            success=True,
            verified=scan.verified,
            error=None if scan.verified else
            f"artifact {artifact['id']} still present on {artifact['host_ip']}",
            timestamp=datetime.utcnow(),
        ))
        log.info(
            "verificationscanner_item", host_ip=artifact["host_ip"],
            artifact_id=artifact["id"], verified=scan.verified,
        )
    log.info("verificationscanner_done", host_ip=host_ip, scanned=len(results))
    return VerificationScannerOutput(results=results)
