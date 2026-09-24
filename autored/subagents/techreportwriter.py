"""TechReportWriter sub-agent — full technical report (spec §7.4).

The LLM writes the Attack Narrative; every structured section (findings
table, foothold inventory, cleanup results, ...) is rendered
deterministically from the redacted state so the model can never mistype
data it was given. Secret values are replaced by
``***REDACTED***(sha256:<8hex>)`` fingerprints before the LLM ever sees
them (plan Review Focus #2) — the same fingerprints the memory writer
(Task 8) stores, so an operator can correlate a report row with a DB row.
"""
import hashlib
import json

from langchain_core.tools import tool
from pydantic import BaseModel

from autored.logging import get_logger
from autored.router import _is_refusal, get_model

log = get_logger("subagents.techreportwriter")

TECH_REPORT_PROMPT = """You are the TechReportWriter sub-agent in AutoRed, a red team automation system.
Write the "## Attack Narrative" section (200-400 words) for the technical
report of this engagement. Tell the story chronologically: how access was
gained, how privileges were escalated, how lateral movement proceeded.
Reference hosts and technique names — never credentials (they are already
redacted in the data below and must stay that way).

Engagement data (JSON, secrets already redacted):
{data_json}

Rules:
- Start with "## Attack Narrative"
- Chronological, technical, precise
- No tables (they are generated deterministically around your narrative)
- No secret values, no hashes, no passwords
"""


class TechReportOutput(BaseModel):
    report_markdown: str
    used_fallback: bool = False


def _redact_secret(value: str) -> str:
    fingerprint = hashlib.sha256(value.encode()).hexdigest()[:8]
    return f"***REDACTED***(sha256:{fingerprint})"


def _redacted_state_dict(state) -> dict:
    """Serialize the state with secrets redacted.

    ``mode="json"`` keeps the dict JSON-serializable (datetimes → ISO
    strings) — this dict feeds ``json.dumps`` in the LLM prompt and the
    report assembly.
    """
    data = state.model_dump(mode="json")
    for secret in data.get("harvested_secrets", []):
        if secret.get("secret_value"):
            secret["secret_value"] = _redact_secret(secret["secret_value"])
    return data


def _findings_table(state_dict: dict) -> str:
    vulns = state_dict.get("vulnerabilities", [])
    if not vulns:
        return "_No findings recorded._"
    lines = ["| Host | Port | Service | CVE | Severity | Title |",
             "|---|---|---|---|---|---|"]
    for v in vulns:
        lines.append(
            f"| {v.get('host_ip', '')} | {v.get('port') or ''} | "
            f"{v.get('service') or ''} | {v.get('cve') or ''} | "
            f"{v.get('severity', '')} | {v.get('title', '')} |"
        )
    return "\n".join(lines)


def _simple_inventory(state_dict: dict, key: str, render) -> str:
    items = state_dict.get(key, [])
    if not items:
        return "_None recorded._"
    return "\n".join(f"- {render(item)}" for item in items)


def _template_tech_report(data: dict) -> str:
    """Deterministic report body — used whole as fallback, sections reused
    around the LLM narrative on the happy path."""
    summary = data.get("summary", {})
    state_dict = data.get("state", {})

    sections = [
        "## Scope",
        "",
        f"- Target: {summary.get('target', 'unknown')}",
        f"- Engagement: {summary.get('engagement_id', 'unknown')}",
        f"- Operator: {summary.get('operator', 'unknown')}",
        f"- Duration: {summary.get('duration_min', 0):.0f} minutes",
        "",
        "## Findings",
        "",
        _findings_table(state_dict),
        "",
        "## Footholds",
        "",
        _simple_inventory(state_dict, "footholds", lambda f: (
            f"{f.get('host_ip')} as {f.get('username')} ({f.get('context')}) "
            f"via {f.get('method')}, access {f.get('access_type')}"
        )),
        "",
        "## Privilege Escalation",
        "",
        _simple_inventory(state_dict, "privesc_attempts", lambda a: (
            f"{a.get('host_ip')}: {a.get('candidate_id', '')} — "
            f"{'SUCCESS' if a.get('success') else 'failed'}"
            f"{' → ' + a.get('new_context') if a.get('new_context') else ''}"
        )),
        "",
        "## Persistence Artifacts",
        "",
        _simple_inventory(state_dict, "persistence_artifacts", lambda p: (
            f"{p.get('host_ip')}: {p.get('method')} (removal command recorded)"
        )),
        "",
        "## Defense Evasion",
        "",
        _simple_inventory(state_dict, "evasion_actions", lambda e: (
            f"{e.get('host_ip')}: {e.get('technique')} — "
            f"{'SUCCESS' if e.get('success') else 'failed'}"
        )),
        "",
        "## Exfiltration",
        "",
        _simple_inventory(state_dict, "exfiltration_proof", lambda x: (
            f"{x.get('method')} from {x.get('source_host')} "
            f"({x.get('data_size_bytes', 0)} bytes) to catch server"
        )),
        "",
        "## Lateral Movement",
        "",
        _simple_inventory(state_dict, "pivots", lambda p: (
            f"to {p.get('target_host')} via {p.get('method')} — "
            f"{'SUCCESS' if p.get('success') else 'failed'}"
        )),
        "",
        "## Cleanup",
        "",
        _simple_inventory(state_dict, "cleanup_results", lambda c: (
            f"{c.get('host_ip')}: {c.get('removal_command')[:60]} — "
            f"{'verified removed' if c.get('verified') else 'NOT VERIFIED'}"
        )),
        "",
        "## Evidence Inventory",
        "",
        _simple_inventory(state_dict, "evidence_paths", lambda e: str(e)),
        "",
        "## Errors",
        "",
        _simple_inventory(state_dict, "errors", lambda e: (
            f"[{e.get('category')}] {e.get('agent')}: {e.get('message')}"
        )),
    ]
    return "\n".join(sections) + "\n"


@tool
async def techreportwriter_subagent(engagement_data: str, engagement_id: str = "") -> TechReportOutput:
    """Generate the technical report body (narrative + deterministic sections).

    Args:
        engagement_data: JSON of {"summary": {...}, "state": {...}} with
            secrets already redacted by the caller via _redacted_state_dict.
        engagement_id: Current engagement ID.

    Returns:
        TechReportOutput with report_markdown and used_fallback flag.
    """
    log.info("techreport_start", engagement_id=engagement_id)
    data = json.loads(engagement_data) if isinstance(engagement_data, str) else engagement_data
    deterministic_body = _template_tech_report(data)

    narrative = ""
    try:
        model = get_model("write_report")
        response = await model.ainvoke(TECH_REPORT_PROMPT.format(
            data_json=json.dumps(data, indent=2),
        ))
        content = response.content if hasattr(response, "content") else str(response)
        if content and not _is_refusal(content):
            narrative = content
        else:
            log.warning("techreport_refused", engagement_id=engagement_id)
    except Exception as e:  # noqa: BLE001 — deliverable must survive LLM failure
        log.warning("techreport_llm_failed", engagement_id=engagement_id, error=str(e))

    used_fallback = narrative == ""
    if used_fallback:
        narrative = (
            "## Attack Narrative\n\n"
            "_LLM narrative unavailable (API failure or refusal) — see the "
            "deterministic sections below for the full activity record._"
        )

    markdown = narrative + "\n" + deterministic_body
    log.info("techreport_done", engagement_id=engagement_id, fallback=used_fallback)
    return TechReportOutput(report_markdown=markdown, used_fallback=used_fallback)
