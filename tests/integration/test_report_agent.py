"""Integration tests for the Report Agent node (Phase 6 Task 9).

Mocks every sub-agent (module-level aliases, the postex.py pattern),
render_pdf, and persist_engagement_memory. Verifies the deliverable
files, state updates, redaction, and the empty-engagement path
(Review Focus #1).

I1 (Phase 3 fix wave): the EventBus travels via
``config["configurable"]["event_bus"]`` (RunnableConfig), NOT via
``state.event_bus``. The Report Agent is full-auto (no HitL gates),
but the bus is accepted for status events and uniform node signatures.
Each test calls ``report_node(state, config)`` directly.
"""
import json
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from autored.agents.report import (
    _build_engagement_summary,
    _build_mitre_records,
    report_node,
)
from autored.models import Foothold, Secret
from autored.models.report import Lesson, MitreMapping, ReportPaths
from autored.models.roe import RulesOfEngagement
from autored.state import EngagementState

PLAINTEXT = "ReportSecret99"


def _roe() -> RulesOfEngagement:
    return RulesOfEngagement(
        engagement_name="t", operator="t", operator_signature="t",
        allowed_ips=["*"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, data_destruction_allowed=False,
        kernel_exploits_allowed=True, hitl_mode="auto_approve",
    )


def _state() -> EngagementState:
    state = EngagementState(
        engagement_id="rep-int-e1", target_scope=["10.0.0.5"],
        operator="tester", rules_of_engagement=_roe(),
    )
    state.harvested_secrets = [
        Secret(host_ip="10.0.0.5", secret_type="password",
               secret_value=PLAINTEXT, source="mimikatz:wdigest/administrator"),
    ]
    state.footholds = [Foothold(
        id="f-1", host_ip="10.0.0.5", username="system", context="system",
        method="ms17_010", access_type="rpc", evidence_path="e.txt",
        established_at=datetime.utcnow(), hypothesis_rank=1,
    )]
    state.summary = ""
    return state


def _sub_agent_mocks():
    """AsyncMock stand-ins for the four report sub-agents."""
    mitre = MagicMock()
    mitre.ainvoke = AsyncMock(return_value=MagicMock(mappings=[MitreMapping(
        technique_id="T1210", technique_name="Exploitation of Remote Services",
        tactic="lateral-movement", source="foothold", detail="ms17_010",
    )]))
    exec_summary = MagicMock()
    exec_summary.ainvoke = AsyncMock(return_value=MagicMock(
        summary_markdown="## Executive Summary\n\nFull chain achieved.", used_fallback=False))
    tech = MagicMock()
    tech.ainvoke = AsyncMock(return_value=MagicMock(
        report_markdown="## Attack Narrative\n\nStory.\n\n## Scope\n\n- t",
        used_fallback=False))
    lessons = MagicMock()
    lessons.ainvoke = AsyncMock(return_value=MagicMock(lessons=[
        Lesson(category="technique_worked", body="ms17_010 worked",
               mitre_technique_id="T1210"),
    ]))
    return mitre, exec_summary, tech, lessons


def _config_with_bus(bus) -> dict:
    """Build a RunnableConfig-shaped dict carrying the EventBus (I1 pattern)."""
    return {"configurable": {"event_bus": bus}}


async def test_report_node_writes_all_deliverables(tmp_path, monkeypatch):
    """Happy path: report.md + lessons.json exist + non-empty, secrets redacted."""
    # Run from a tmp_path so engagements/<id>/ lands inside the test sandbox.
    monkeypatch.chdir(tmp_path)
    state = _state()
    mitre, exec_summary, tech, lessons = _sub_agent_mocks()
    config = _config_with_bus(None)
    with patch.multiple(
        "autored.agents.report",
        mitremapper_subagent=mitre,
        execsummarywriter_subagent=exec_summary,
        techreportwriter_subagent=tech,
        lessonextractor_subagent=lessons,
    ), patch("autored.agents.report.render_pdf",
             AsyncMock(return_value=None)), patch(
        "autored.agents.report.persist_engagement_memory",
        AsyncMock(return_value=MagicMock(findings_written=0))):

        result = await report_node(state, config)

    assert result["phase"] == "done"
    assert result["summary"]  # one-line outcome set
    assert len(result["lessons"]) == 1
    assert result["lessons"][0].category == "technique_worked"
    assert len(result["mitre_mappings"]) == 1
    assert isinstance(result["report_paths"], ReportPaths)
    assert result["report_paths"].pdf_path is None  # render_pdf mocked to None

    # The node writes into engagements/<id>/ relative to CWD.
    report_path = Path(result["report_paths"].markdown_path)
    assert report_path.exists()
    content = report_path.read_text()
    assert "## Executive Summary" in content
    assert "## MITRE ATT&CK Matrix" in content
    assert PLAINTEXT not in content  # Review Focus #2 — no secret in report

    lessons_path = Path(result["report_paths"].lessons_path)
    assert lessons_path.exists()
    lesson_payload = json.loads(lessons_path.read_text())
    assert lesson_payload[0]["category"] == "technique_worked"
    assert PLAINTEXT not in lessons_path.read_text()


async def test_report_node_on_empty_engagement(tmp_path, monkeypatch):
    """Review Focus #1 — zero hosts / findings still produces a report."""
    monkeypatch.chdir(tmp_path)
    state = EngagementState(
        engagement_id="rep-int-empty", target_scope=["10.0.0.99"],
        operator="t", rules_of_engagement=_roe(),
    )
    mitre, exec_summary, tech, lessons = _sub_agent_mocks()
    config = _config_with_bus(None)
    with patch.multiple(
        "autored.agents.report",
        mitremapper_subagent=mitre,
        execsummarywriter_subagent=exec_summary,
        techreportwriter_subagent=tech,
        lessonextractor_subagent=lessons,
    ), patch("autored.agents.report.render_pdf",
             AsyncMock(return_value=None)), patch(
        "autored.agents.report.persist_engagement_memory",
        AsyncMock(return_value=MagicMock(findings_written=0))):

        result = await report_node(state, config)  # must not raise

    assert result["phase"] == "done"
    report_path = Path(result["report_paths"].markdown_path)
    assert report_path.exists()
    # Empty engagement content: minimal report body is written and is non-empty.
    assert report_path.read_text().strip()


def test_build_engagement_summary_counts():
    state = _state()
    summary = _build_engagement_summary(state)
    assert summary["engagement_id"] == "rep-int-e1"
    assert summary["footholds"][0]["method"] == "ms17_010"
    assert summary["cleanup_all_verified"] is True  # no cleanup results → vacuous
    assert "outcome" in summary


def test_build_mitre_records_shape():
    records = _build_mitre_records(_state())
    assert records["footholds"][0]["method"] == "ms17_010"
    assert records["cred_methods"]  # mimikatz parsed from secret sources
    assert "recon_hosts" in records
