"""Report Agent — the final LangGraph node (spec §6.7, Phase 6).

Orchestrates the four report sub-agents (MITREMapper → ExecSummaryWriter
→ TechReportWriter → LessonExtractor), assembles the markdown deliverable,
renders the PDF (graceful degradation), persists cross-engagement memory,
and writes ``lessons.json``. Full-auto — no HitL gates (spec §2.4).

Robustness contract (plan Review Focus #1): this node closes the graph.
A crash here destroys the entire engagement's deliverable, so every
sub-agent already carries a deterministic fallback and every write is
best-effort with structured logging.

I1 (Phase 3 fix wave): the EventBus travels via
``config["configurable"]["event_bus"]`` (RunnableConfig), NOT via
``state.event_bus``. LangGraph's reducer round-trips state through
``model_dump() + model_validate()`` which strips the
``__pydantic_extra__`` dict where ``state.event_bus = ...`` was stored
under ``extra="allow"``. The Report Agent is full-auto (no HitL gates),
so the bus is only a status-event channel — but the two-arg signature
is kept for uniformity with the other Phase 1–5 nodes.

The Phase 1 stub ``report_node_phase1`` is preserved so existing graph
wiring (``autored/graph.py``) keeps working — Phase 6 Task 10 wires
the full ``report_node`` into the Phase 6 graph builder.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from langchain_core.runnables import RunnableConfig

from autored.logging import get_logger
from autored.models.report import ReportPaths
from autored.reporting.markdown_report import assemble_markdown_report
from autored.reporting.memory_writer import persist_engagement_memory
from autored.reporting.pdf import render_pdf
from autored.state import EngagementState
from autored.subagents import (
    execsummarywriter as _execsummarywriter_mod,
)
from autored.subagents import (
    lessonextractor as _lessonextractor_mod,
)
from autored.subagents import (
    mitremapper as _mitremapper_mod,
)
from autored.subagents import (
    techreportwriter as _techreportwriter_mod,
)
from autored.subagents.techreportwriter import _redacted_state_dict

log = get_logger("agents.report")

# Module-level aliases so integration tests patch
# ``autored.agents.report.<name>_subagent`` (same pattern as postex.py).
mitremapper_subagent = _mitremapper_mod.mitremapper_subagent
execsummarywriter_subagent = _execsummarywriter_mod.execsummarywriter_subagent
techreportwriter_subagent = _techreportwriter_mod.techreportwriter_subagent
lessonextractor_subagent = _lessonextractor_mod.lessonextractor_subagent


def _build_engagement_summary(state: EngagementState) -> dict:
    """One dict feeding ExecSummaryWriter, LessonExtractor, and the node.

    Counts are derived from the populated state collections; footholds /
    pivots are serialized to a small dict per record (no secrets — the
    LLM-facing summary never carries credential material).
    """
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for vuln in state.vulnerabilities:
        if vuln.severity in severity_counts:
            severity_counts[vuln.severity] += 1

    cleanup_results = list(getattr(state, "cleanup_results", []))
    unverified = [c for c in cleanup_results if not c.verified]

    if state.footholds:
        outcome = (
            f"{len(state.footholds)} foothold(s), "
            f"{sum(1 for a in state.privesc_attempts if a.success)} privesc, "
            f"{sum(1 for p in state.pivots if p.success)} pivot(s)"
        )
    elif state.vulnerabilities:
        outcome = "findings identified, no foothold achieved"
    else:
        outcome = "no findings recorded"

    duration_min = max(
        0.0, (datetime.utcnow() - state.started_at).total_seconds() / 60,
    )

    return {
        "engagement_id": state.engagement_id,
        "target": ", ".join(state.target_scope),
        "operator": state.operator,
        "duration_min": duration_min,
        "hosts": len(state.hosts),
        "services": len(state.services),
        "findings": len(state.vulnerabilities),
        "findings_by_severity": severity_counts,
        "footholds": [
            {"method": f.method, "host_ip": f.host_ip, "username": f.username}
            for f in state.footholds
        ],
        "privesc_successes": sum(1 for a in state.privesc_attempts if a.success),
        "pivots": [
            {"method": p.method, "target_host": p.target_host, "success": p.success}
            for p in state.pivots
        ],
        "sub_engagements": len(getattr(state, "sub_engagements", [])),
        "cleanup_all_verified": not unverified,
        "unverified_cleanups": [
            {"host_ip": c.host_ip, "removal_command": c.removal_command}
            for c in unverified
        ],
        "errors": [
            {"category": e.category, "agent": e.agent, "message": e.message}
            for e in state.errors
        ],
        "outcome": outcome,
    }


def _build_mitre_records(state: EngagementState) -> dict:
    """Serialize state into the MITREMapper input shape (Task 3).

    The MITREMapper is rules-based — never an LLM — so the record shape
    here is exactly the keyword set the mapper matches against. ``cred_methods``
    parses the tool prefix from each harvested secret's ``source``
    (``"mimikatz:wdigest/administrator"`` → ``"mimikatz"``).
    """
    cred_methods: set[str] = set()
    for secret in state.harvested_secrets:
        source = (secret.source or "").split(":")[0]
        if source:
            cred_methods.add(source)

    return {
        "recon_hosts": len(state.hosts),
        "vuln_scans": 1 if state.vulnerabilities else 0,
        "footholds": [
            {"method": f.method, "access_type": f.access_type, "host_ip": f.host_ip}
            for f in state.footholds
        ],
        "privesc_attempts": [
            {
                "technique": a.candidate_id,
                "category": getattr(a, "category", ""),
                "success": a.success,
            }
            for a in state.privesc_attempts
        ],
        "persistence_artifacts": [
            {"method": p.method, "host_ip": p.host_ip}
            for p in state.persistence_artifacts
        ],
        "evasion_actions": [
            {"technique": e.technique} for e in state.evasion_actions
        ],
        "exfiltration_proof": [
            {"method": x.method} for x in state.exfiltration_proof
        ],
        "pivots": [
            {"method": p.method, "target_host": p.target_host, "success": p.success}
            for p in state.pivots
        ],
        "tunnels": [{"tool": t.tool} for t in getattr(state, "tunnels", [])],
        "cred_methods": sorted(cred_methods),
        "bloodhound": any(
            "bloodhound" in (s.source or "").lower()
            for s in state.harvested_secrets
        ) or bool(getattr(state, "trust_relationships", [])),
    }


def _get_bus(config: RunnableConfig | None) -> object | None:
    """Extract EventBus from RunnableConfig (Phase 3 fix wave I1).

    Returns ``None`` in headless mode — the Report Agent is full-auto
    and never blocks on the bus, but emits status events when present.
    """
    return (config or {}).get("configurable", {}).get("event_bus")


async def report_node(
    state: EngagementState, config: RunnableConfig
) -> dict:
    """LangGraph node: generate the engagement deliverable (spec §6.7).

    Eight-step flow:
      1. Build summary + MITRE records (pure helpers, no I/O).
      2. MITRE mapping (rules-based, via ``mitremapper_subagent``).
      3. Executive summary (LLM + template fallback, via
         ``execsummarywriter_subagent``).
      4. Technical report (LLM narrative + deterministic tables, via
         ``techreportwriter_subagent`` — secrets redacted upstream by
         ``_redacted_state_dict`` so the LLM never sees them).
      5. Assemble + write markdown FIRST (deliverable of record).
      6. PDF rendering (graceful degradation — ``None`` is legal).
      7. Lessons extraction (LLM + deterministic fallback, via
         ``lessonextractor_subagent``).
      8. Memory persistence (``persist_engagement_memory``) + write
         ``lessons.json``.

    Returns the state-dict patch: ``phase="done"``, the one-line outcome
    summary, lessons, MITRE mappings, ``ReportPaths`` (markdown always
    set, PDF possibly ``None``), and incremented ``iteration_count``.
    """
    log.info("report_start", engagement_id=state.engagement_id)
    engagement_id = state.engagement_id

    # Touch the bus so the linter / future status events can use it
    # without a second extraction (the Report Agent currently emits no
    # status events — T10 wires the dashboard progress bar).
    _get_bus(config)

    # Step 1: build the shared input dicts.
    summary = _build_engagement_summary(state)
    mitre_records = _build_mitre_records(state)

    # Step 2: MITRE mapping (rules-based, cannot fail loudly).
    mitre_output = await mitremapper_subagent.ainvoke({
        "engagement_records": json.dumps(mitre_records),
        "engagement_id": engagement_id,
    })
    mitre_mappings = list(getattr(mitre_output, "mappings", []) or [])

    # Step 3: executive summary (LLM + template fallback).
    exec_output = await execsummarywriter_subagent.ainvoke({
        "engagement_summary": json.dumps(summary),
        "engagement_id": engagement_id,
    })
    if getattr(exec_output, "used_fallback", False):
        log.warning("report_exec_summary_fallback", engagement_id=engagement_id)

    # Step 4: technical report (narrative + deterministic sections,
    # secrets redacted before the LLM ever sees them).
    tech_data = {
        "summary": summary,
        "state": _redacted_state_dict(state),
    }
    tech_output = await techreportwriter_subagent.ainvoke({
        "engagement_data": json.dumps(tech_data),
        "engagement_id": engagement_id,
    })
    if getattr(tech_output, "used_fallback", False):
        log.warning("report_tech_report_fallback", engagement_id=engagement_id)

    # Step 5: assemble + write markdown FIRST (deliverable of record).
    markdown = assemble_markdown_report(
        state,
        exec_output.summary_markdown,
        tech_output.report_markdown,
        mitre_mappings,
    )
    report_dir = Path("engagements") / engagement_id
    report_dir.mkdir(parents=True, exist_ok=True)
    md_path = report_dir / "report.md"
    md_path.write_text(markdown)

    # Step 6: PDF (graceful degradation — Review Focus #5).
    pdf_path = await render_pdf(markdown, engagement_id)

    # Step 7: lessons for cross-engagement memory.
    lessons_summary = {
        "footholds": summary["footholds"],
        "pivots": summary["pivots"],
        "unverified_cleanups": summary["unverified_cleanups"],
        "errors": summary["errors"],
    }
    lessons_output = await lessonextractor_subagent.ainvoke({
        "engagement_summary": json.dumps(lessons_summary),
        "engagement_id": engagement_id,
    })
    lessons = list(getattr(lessons_output, "lessons", []) or [])

    # Step 8: persist cross-engagement memory (SQLite + Chroma, isolated).
    try:
        from autored.persistence.chroma_store import ChromaStore
        chroma = ChromaStore()
    except Exception as e:  # noqa: BLE001 — chroma init failure degrades to None
        log.warning(
            "report_chroma_unavailable",
            engagement_id=engagement_id, error=str(e),
        )
        chroma = None
    memory_result = await persist_engagement_memory(state, chroma=chroma)
    if memory_result.db_error or memory_result.chroma_error:
        log.warning(
            "report_memory_partial",
            engagement_id=engagement_id,
            db_error=memory_result.db_error,
            chroma_error=memory_result.chroma_error,
        )

    # Write ``lessons.json`` (spec §3.2 layout — no secrets; lessons
    # are validated upstream by the LessonExtractor). ``mode="json"``
    # renders datetimes as ISO strings (the SQLite table stores TEXT).
    lessons_path = report_dir / "lessons.json"
    lessons_path.write_text(json.dumps(
        [lesson.model_dump(mode="json") for lesson in lessons], indent=2,
    ))

    report_paths = ReportPaths(
        markdown_path=str(md_path),
        pdf_path=str(pdf_path) if pdf_path else None,
        lessons_path=str(lessons_path),
    )

    log.info(
        "report_done",
        engagement_id=engagement_id,
        md=str(md_path), pdf=str(pdf_path), lessons=len(lessons),
    )

    return {
        "phase": "done",
        "summary": summary["outcome"],
        "lessons": lessons,
        "mitre_mappings": mitre_mappings,
        "report_paths": report_paths,
        "iteration_count": state.iteration_count + 1,
    }


# ---------------------------------------------------------------------------
# Phase 1 terminal stub — preserved so existing graph wiring
# (``autored/graph.py``) keeps working. Phase 6 Task 10 swaps the Phase 1
# graph builder for the Phase 6 one, which references ``report_node`` above.
# ---------------------------------------------------------------------------
async def report_node_phase1(
    state: EngagementState, config: RunnableConfig
) -> dict:
    """Phase 1 stub: mark the engagement phase as done.

    The full Report Agent (``report_node`` above) replaces this stub in
    the Phase 6 graph builder (Task 10). For Phase 1 we only need a
    terminal node so the graph has a reachable sink after a successful
    recon.

    ``config`` is accepted for I1 (Phase 3 fix wave) consistency with
    the other Phase 1-3 nodes. The Report Agent stub doesn't currently
    consume the EventBus, but Phase 6's full Report Agent may use it
    for progress events (PDF rendering bar, evidence packaging updates).
    """
    log.info("report_phase1_stub", engagement_id=state.engagement_id)
    return {"phase": "done"}
