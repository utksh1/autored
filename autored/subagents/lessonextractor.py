"""LessonExtractor sub-agent — cross-engagement memory seeds (spec §7.4).

Lessons are the payload of the cross-engagement memory layer (spec §3.1
layer 3): "last time CVE-X, this exploit worked". The LLM proposes them
from the engagement summary; a validator enforces the SQLite category set
and nulls any technique ID not present in the embedded MITRE index —
an invented ID is worse than a missing one, because downstream the Vuln
Agent will trust it. Deterministic fallback lessons come from the
engagement's own outcome records.
"""
import json

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from autored.logging import get_logger
from autored.models.report import Lesson
from autored.router import _is_refusal, get_model
from autored.subagents.mitremapper import MITRE_TECHNIQUES

log = get_logger("subagents.lessonextractor")

LESSON_EXTRACT_PROMPT = """You are the LessonExtractor sub-agent in AutoRed, a red team automation system.
Extract 3-8 durable lessons from this engagement that will help future
engagements (they are stored in a cross-engagement memory other AutoRed
runs query).

Engagement summary (JSON):
{summary_json}

Return ONLY a JSON array, each element:
{{"category": "<technique_worked|cve_exploited|tool_issue|opsec_failure|misconfiguration|other>",
  "body": "<one specific, actionable sentence>",
  "mitre_technique_id": "<T.... or null>"}}

Rules:
- Be specific: "wmiexec over NTLM hash succeeded against SRV02 (GoAD)" not "lateral movement works"
- Only cite MITRE ATT&CK IDs you are certain exist; null otherwise
- No credentials or hashes in lesson bodies
"""


class LessonExtractorOutput(BaseModel):
    lessons: list[Lesson] = Field(default_factory=list)


def _validate_lesson_payload(payload: list) -> list[Lesson]:
    valid_categories = {
        "technique_worked", "cve_exploited", "tool_issue",
        "opsec_failure", "misconfiguration", "other",
    }
    lessons: list[Lesson] = []
    for row in payload:
        if not isinstance(row, dict):
            continue
        category = row.get("category")
        body = (row.get("body") or "").strip()
        if category not in valid_categories or not body:
            continue
        mitre_id = row.get("mitre_technique_id")
        if mitre_id and mitre_id not in MITRE_TECHNIQUES:
            mitre_id = None  # invented ID → strip, keep the lesson
        lessons.append(Lesson(category=category, body=body, mitre_technique_id=mitre_id))
    return lessons


def _fallback_lessons(summary: dict) -> list[Lesson]:
    lessons: list[Lesson] = []
    for foothold in summary.get("footholds", []):
        lessons.append(Lesson(
            category="technique_worked",
            body=f"{foothold.get('method')} yielded a foothold on "
                 f"{foothold.get('host_ip')} as {foothold.get('username')}",
        ))
    for pivot in summary.get("pivots", []):
        if pivot.get("success"):
            lessons.append(Lesson(
                category="technique_worked",
                body=f"{pivot.get('method')} pivot to {pivot.get('target_host')} succeeded",
            ))
    for cleanup in summary.get("unverified_cleanups", []):
        lessons.append(Lesson(
            category="tool_issue",
            body=f"cleanup on {cleanup.get('host_ip')} could not be verified removed",
        ))
    return lessons


@tool
async def lessonextractor_subagent(engagement_summary: str, engagement_id: str = "") -> LessonExtractorOutput:
    """Extract lessons for the cross-engagement memory.

    LLM-proposed with validation (categories + MITRE index) and a
    deterministic fallback from the engagement's outcome records.

    Args:
        engagement_summary: JSON summary with footholds, pivots,
            unverified_cleanups, and errors lists.
        engagement_id: Current engagement ID.

    Returns:
        LessonExtractorOutput with validated Lesson records.
    """
    log.info("lessonextract_start", engagement_id=engagement_id)
    summary = json.loads(engagement_summary) if isinstance(engagement_summary, str) else engagement_summary

    lessons: list[Lesson] = []
    try:
        model = get_model("write_report")
        response = await model.ainvoke(LESSON_EXTRACT_PROMPT.format(
            summary_json=json.dumps(summary, indent=2),
        ))
        content = response.content if hasattr(response, "content") else str(response)
        if content and not _is_refusal(content):
            try:
                # Tolerate code fences around the JSON array.
                text = content.strip()
                if text.startswith("```"):
                    text = text.split("\n", 1)[1].rsplit("```", 1)[0]
                payload = json.loads(text)
                lessons = _validate_lesson_payload(payload)
            except json.JSONDecodeError as e:
                log.warning("lessonextract_bad_json", engagement_id=engagement_id, error=str(e))
        else:
            log.warning("lessonextract_refused", engagement_id=engagement_id)
    except Exception as e:  # noqa: BLE001 — lessons must survive LLM failure
        log.warning("lessonextract_llm_failed", engagement_id=engagement_id, error=str(e))

    if not lessons:
        lessons = _fallback_lessons(summary)

    log.info("lessonextract_done", engagement_id=engagement_id, lessons=len(lessons))
    return LessonExtractorOutput(lessons=lessons)
