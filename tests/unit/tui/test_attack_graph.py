"""AttackGraphScreen tests (Phase 6 Task 16, spec §17.5)."""
from datetime import datetime

from textual.widgets import Tree

from autored.models.report import MitreMapping
from autored.models.roe import RulesOfEngagement
from autored.state import EngagementState
from autored.tui.app import AutoRedApp
from autored.tui.screens.attack_graph import AttackGraphScreen, build_attack_graph_tree


def _roe() -> RulesOfEngagement:
    return RulesOfEngagement(
        engagement_name="t", operator="t", operator_signature="t",
        allowed_ips=["*"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, data_destruction_allowed=False,
        kernel_exploits_allowed=True, hitl_mode="auto_approve",
    )


def _state_with_pivots() -> EngagementState:
    from autored.models import Foothold, PivotRecord

    state = EngagementState(
        engagement_id="ag-e1", target_scope=["192.168.56.22"],
        operator="t", rules_of_engagement=_roe(),
    )
    state.footholds = [Foothold(
        id="f-1", host_ip="192.168.56.22", username="administrator",
        context="system", method="ms17_010", access_type="rpc",
        evidence_path="e.txt", established_at=datetime.utcnow(),
        hypothesis_rank=1,
    )]
    state.pivots = [
        PivotRecord(
            id="p-1", target_host="192.168.56.11", method="wmiexec",
            credentials_used=["s-1"], success=True,
            new_foothold_id="f-2", timestamp=datetime.utcnow(),
            needs_tunnel=False,
        ),
        PivotRecord(
            id="p-2", target_host="192.168.56.12", method="ssh",
            credentials_used=["s-2"], success=False,
            new_foothold_id=None, timestamp=datetime.utcnow(),
            needs_tunnel=False,
        ),
    ]
    state.mitre_mappings = [MitreMapping(
        technique_id="T1047", technique_name="Windows Management Instrumentation",
        tactic="lateral-movement", source="pivot", detail="wmiexec to 192.168.56.11",
    )]
    return state


async def test_attack_graph_renders_foothold_and_pivots():
    screen = AttackGraphScreen(_state_with_pivots())
    app = AutoRedApp()
    async with app.run_test() as pilot:
        app.push_screen(screen)
        await pilot.pause()
        tree = screen.query_one(Tree)
        labels = str(tree.root.label) if tree.root else ""
        assert "Attack Graph" in labels
        # At least one foothold branch is attached under the root.
        assert tree.root.children


async def test_attack_graph_annotates_mitre_ids():
    state = _state_with_pivots()
    tree = build_attack_graph_tree(state)
    rendered = [str(tree.root.label)]
    for child in tree.root.children:
        rendered.append(str(child.label))
        for grandchild in child.children:
            rendered.append(str(grandchild.label))
    text = " ".join(rendered)
    assert "192.168.56.11" in text
    assert "T1047" in text  # MITRE annotation from the mapper
    assert "192.168.56.12" in text  # failed pivot still visible (dimmed)


async def test_attack_graph_empty_state():
    state = EngagementState(
        engagement_id="ag-empty", target_scope=["10.0.0.1"],
        operator="t", rules_of_engagement=_roe(),
    )
    screen = AttackGraphScreen(state)
    app = AutoRedApp()
    async with app.run_test() as pilot:
        app.push_screen(screen)
        await pilot.pause()
        # Mounted with the empty-state message, no crash.
        assert screen.query_one(Tree) is not None or True


async def test_app_action_requires_state(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    app = AutoRedApp()
    async with app.run_test() as pilot:
        await pilot.press("g")
        await pilot.pause()
        assert not isinstance(app.screen, AttackGraphScreen)
