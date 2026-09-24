from __future__ import annotations

import pytest

from autored.config import RulesOfEngagement
from autored.state import EngagementState


def _basic_roe():
    return RulesOfEngagement(
        engagement_name="t", operator="o", operator_signature="s",
        allowed_ips=["0.0.0.0/0"], allowed_techniques=["*"],
        persistence_allowed=False, evasion_allowed=False,
        exfiltration_allowed=False, data_destruction_allowed=False,
        kernel_exploits_allowed=False, hitl_mode="always_ask",
    )


def _sandbox_state() -> EngagementState:
    """Build a minimal EngagementState for sandbox tests."""
    return EngagementState(
        target_scope=["10.10.10.5"],
        operator="tester",
        rules_of_engagement=_basic_roe(),
    )


def test_engagement_state_minimal():
    s = EngagementState(
        target_scope=["10.10.10.5"],
        operator="tester",
        rules_of_engagement=_basic_roe(),
    )
    assert s.engagement_id  # auto-uuid
    assert s.phase == "recon"
    assert s.hosts == []
    assert s.services == []
    assert s.vulnerabilities == []
    assert s.attack_hypotheses == []  # Phase 2 field, default empty
    assert s.errors == []


def test_engagement_state_serializes_to_json():
    s = EngagementState(
        target_scope=["10.10.10.5"],
        operator="tester",
        rules_of_engagement=_basic_roe(),
    )
    j = s.model_dump_json()
    assert "engagement_id" in j
    assert "rules_of_engagement" in j


def test_engagement_state_phase_literal_rejects_invalid():
    s = EngagementState(
        target_scope=["10.10.10.5"], operator="t", rules_of_engagement=_basic_roe(),
    )
    with pytest.raises(Exception):
        s.phase = "bogus"


class TestPhase5StateFields:
    """Phase 5 lateral/cleanup state fields default to empty (Task 1)."""

    def _state(self) -> EngagementState:
        return EngagementState(
            target_scope=["10.10.10.5"],
            operator="op",
            rules_of_engagement=RulesOfEngagement(
                engagement_name="t", operator="op", operator_signature="s",
                allowed_ips=["0.0.0.0/0"], allowed_techniques=["*"],
                persistence_allowed=True, evasion_allowed=True,
                exfiltration_allowed=True, kernel_exploits_allowed=True,
            ),
        )

    def test_phase5_fields_default_empty(self):
        s = self._state()
        assert s.pivots == []
        assert s.tunnels == []
        assert s.sub_engagements == []
        assert s.movement_paths == []
        assert s.cleanup_results == []

    def test_phase_literal_includes_lateral_and_cleanup(self):
        s = self._state()
        s.phase = "lateral"
        assert s.phase == "lateral"
        s.phase = "cleanup"
        assert s.phase == "cleanup"

    def test_state_serializes_phase5_fields(self):
        from autored.models.lateral import PivotRecord
        s = self._state()
        s.pivots.append(PivotRecord(target_host="10.0.0.2", method="wmiexec"))
        dumped = s.model_dump()
        assert dumped["pivots"][0]["target_host"] == "10.0.0.2"
        roundtrip = EngagementState.model_validate(dumped)
        assert roundtrip.pivots[0].method == "wmiexec"


def test_state_has_phase6_report_fields():
    """Phase 6 adds lessons / mitre_mappings / report_paths (default empty)."""
    from autored.models.report import Lesson, MitreMapping, ReportPaths

    state = _sandbox_state()
    assert state.lessons == []
    assert state.mitre_mappings == []
    assert state.report_paths is None

    state.lessons = [Lesson(category="other", body="test lesson")]
    state.mitre_mappings = [MitreMapping(
        technique_id="T1046", technique_name="Network Service Discovery",
        tactic="discovery", source="recon", detail="nmap sweep",
    )]
    state.report_paths = ReportPaths(
        markdown_path="engagements/x/report.md",
        pdf_path=None,
        lessons_path="engagements/x/lessons.json",
    )
    assert state.lessons[0].body == "test lesson"
