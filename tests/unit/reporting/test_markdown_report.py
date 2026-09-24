"""Unit tests for report markdown assembly (Phase 6 Task 9)."""

from autored.models.report import MitreMapping
from autored.models.roe import RulesOfEngagement
from autored.reporting.markdown_report import assemble_markdown_report
from autored.state import EngagementState


def _roe() -> RulesOfEngagement:
    return RulesOfEngagement(
        engagement_name="t", operator="t", operator_signature="t",
        allowed_ips=["*"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, data_destruction_allowed=False,
        kernel_exploits_allowed=True, hitl_mode="auto_approve",
    )


def _state() -> EngagementState:
    return EngagementState(
        engagement_id="rep-e1", target_scope=["10.0.0.5"],
        operator="tester", rules_of_engagement=_roe(),
    )


def test_assembled_report_has_all_sections():
    mappings = [MitreMapping(
        technique_id="T1210", technique_name="Exploitation of Remote Services",
        tactic="lateral-movement", source="foothold", detail="ms17_010 on 10.0.0.5",
    )]
    md = assemble_markdown_report(
        _state(),
        exec_markdown="## Executive Summary\n\nGreat success.",
        tech_markdown="## Scope\n\n- Target: 10.0.0.5",
        mitre_mappings=mappings,
    )
    assert md.startswith("# AutoRed Engagement Report")
    assert "rep-e1" in md
    assert "## Executive Summary" in md
    assert "## Scope" in md
    assert "## MITRE ATT&CK Matrix" in md
    assert "T1210" in md
    assert "Exploitation of Remote Services" in md


def test_mitre_section_renders_empty_placeholder():
    md = assemble_markdown_report(
        _state(), exec_markdown="## Executive Summary\n\nx",
        tech_markdown="## Scope\n\n- y", mitre_mappings=[],
    )
    assert "_No ATT&CK-mapped activity recorded._" in md
