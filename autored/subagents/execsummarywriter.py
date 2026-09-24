"""ExecSummaryWriter sub-agent — one-page non-technical summary (spec §7.4).

LLM-written via ``get_model("write_report")`` with a deterministic
template fallback: an API failure or refusal can never cost the operator
the engagement deliverable (plan Review Focus #3).
"""
import json

from langchain_core.tools import tool
from pydantic import BaseModel

from autored.logging import get_logger
from autored.router import _is_refusal, get_model

log = get_logger("subagents.execsummarywriter")

EXEC_SUMMARY_PROMPT = """You are the ExecSummaryWriter sub-agent in AutoRed, a red team automation system.
Write a one-page executive summary of this engagement for a non-technical
stakeholder. Plain language, no command lines, no credential material.

Engagement facts (JSON):
{summary_json}

Rules:
- Start with "## Executive Summary"
- Cover: what was tested, what was achieved (footholds, privilege escalation,
  lateral movement), overall risk in one sentence, and cleanup confirmation
- 150-300 words. No tables. No secrets or hashes.
"""


class ExecSummaryOutput(BaseModel):
    summary_markdown: str
    used_fallback: bool = False


def _parse_summary_dict(engagement_summary: str) -> dict:
    if isinstance(engagement_summary, dict):
        return engagement_summary
    return json.loads(engagement_summary)


def _template_exec_summary(summary: dict) -> str:
    """Deterministic fallback — always renders the key facts."""
    severity = summary.get("findings_by_severity", {})
    crit = severity.get("critical", 0)
    high = severity.get("high", 0)
    lines = [
        "## Executive Summary",
        "",
        f"**Engagement:** {summary.get('engagement_id', 'unknown')} "
        f"against {summary.get('target', 'unknown target')}.",
        "",
        f"AutoRed mapped **{summary.get('hosts', 0)} host(s)** and "
        f"**{summary.get('services', 0)} service(s)**, and identified "
        f"**{summary.get('findings', 0)} finding(s)** "
        f"({crit} critical, {high} high).",
        "",
        f"The engagement achieved **{summary.get('footholds', 0)} foothold(s)**, "
        f"**{summary.get('privesc_successes', 0)} successful privilege escalation(s)**, "
        f"and **{summary.get('pivots', 0)} lateral pivot(s)**.",
        "",
        f"Outcome: {summary.get('outcome', 'engagement completed')}.",
        "",
    ]
    if summary.get("cleanup_all_verified"):
        lines.append("All engagement artifacts were removed and verified during cleanup.")
    else:
        lines.append(
            "Cleanup was performed; some artifacts could not be verified removed — "
            "see the technical report for the artifact inventory."
        )
    return "\n".join(lines)


@tool
async def execsummarywriter_subagent(engagement_summary: str, engagement_id: str = "") -> ExecSummaryOutput:
    """Generate a one-page executive summary of the engagement.

    LLM-written with a deterministic template fallback on API failure
    or refusal — the deliverable is never lost.

    Args:
        engagement_summary: JSON engagement summary (built by the Report Agent).
        engagement_id: Current engagement ID.

    Returns:
        ExecSummaryOutput with summary_markdown and used_fallback flag.
    """
    log.info("execsummary_start", engagement_id=engagement_id)
    summary = _parse_summary_dict(engagement_summary)

    try:
        model = get_model("write_report")
        response = await model.ainvoke(EXEC_SUMMARY_PROMPT.format(
            summary_json=json.dumps(summary, indent=2),
        ))
        content = response.content if hasattr(response, "content") else str(response)
        if content and not _is_refusal(content):
            log.info("execsummary_done", engagement_id=engagement_id, fallback=False)
            return ExecSummaryOutput(summary_markdown=content, used_fallback=False)
        log.warning("execsummary_refused", engagement_id=engagement_id)
    except Exception as e:  # noqa: BLE001 — deliverable must survive LLM failure
        log.warning("execsummary_llm_failed", engagement_id=engagement_id, error=str(e))

    log.info("execsummary_done", engagement_id=engagement_id, fallback=True)
    return ExecSummaryOutput(
        summary_markdown=_template_exec_summary(summary), used_fallback=True,
    )
