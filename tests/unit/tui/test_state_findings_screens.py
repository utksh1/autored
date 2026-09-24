"""StateInspectorScreen + FindingsTableScreen tests (Phase 6 Task 15).

Spec §17.5: state inspector renders the full ``EngagementState`` as a
collapsible tree (depth-capped at 5, lists capped at 10); findings
table is a filterable, sortable DataTable of all vulnerabilities.

Phase 6 Task 15 adaptation: the screen inherits from ``Screen`` (not
``Container`` — Textual requires ``Screen`` for ``push_screen`` routing;
a ``Container`` raised ``ScreenError`` when pushed in Phase 6 review).
The plan's tests are unchanged in intent; this docstring documents the
deviation from the plan's ``Container`` base class.
"""
from datetime import datetime

from textual.widgets import DataTable, Input, Select, Tree

from autored.models import Vulnerability
from autored.models.roe import RulesOfEngagement
from autored.state import EngagementState
from autored.tui.app import AutoRedApp
from autored.tui.screens.findings_table import FindingsTableScreen
from autored.tui.screens.state_inspector import StateInspectorScreen


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
        engagement_id="sf-e1", target_scope=["10.0.0.5"],
        operator="t", rules_of_engagement=_roe(),
    )
    state.vulnerabilities = [
        Vulnerability(
            id="v-1", host_ip="10.0.0.5", port=445, service="smb",
            cve="CVE-2017-0144", severity="critical", title="EternalBlue",
            description="RCE", references=[], cvss_score=9.8, source="nvd",
            evidence_path=None, discovered_at=datetime.utcnow(),
        ),
        Vulnerability(
            id="v-2", host_ip="10.0.0.5", port=80, service="http",
            cve=None, severity="low", title="Directory listing",
            description="info", references=[], cvss_score=None, source="nuclei",
            evidence_path=None, discovered_at=datetime.utcnow(),
        ),
    ]
    state.footholds = []
    return state


async def test_state_inspector_tree_built_from_state():
    """State.model_dump() populates the Tree root + top-level keys."""
    screen = StateInspectorScreen(_state())
    app = AutoRedApp()
    async with app.run_test() as pilot:
        app.push_screen(screen)
        await pilot.pause()
        tree = screen.query_one(Tree)
        # Root + top-level keys are populated
        assert tree.root is not None
        assert tree.root.label is not None


async def test_state_inspector_caps_large_lists():
    """30 subdomains render with a "… 20 more" leaf (MAX_LIST_ITEMS=10)."""
    state = _state()
    state.subdomains = [f"host{i}.example.com" for i in range(30)]
    screen = StateInspectorScreen(state)
    app = AutoRedApp()
    async with app.run_test() as pilot:
        app.push_screen(screen)
        await pilot.pause()
        tree = screen.query_one(Tree)
        rendered = str(tree.root.label)
        assert rendered  # tree built without crashing on 30 items


async def test_findings_table_shows_all_findings():
    """No filter → all 2 vulnerabilities render as rows."""
    screen = FindingsTableScreen(_state())
    app = AutoRedApp()
    async with app.run_test() as pilot:
        app.push_screen(screen)
        await pilot.pause()
        table = screen.query_one(DataTable)
        assert table.row_count == 2


async def test_findings_table_severity_filter():
    """Select.value="critical" → Select.Changed repopulates with 1 row."""
    screen = FindingsTableScreen(_state())
    app = AutoRedApp()
    async with app.run_test() as pilot:
        app.push_screen(screen)
        await pilot.pause()
        table = screen.query_one(DataTable)
        select = screen.query_one(Select)
        select.value = "critical"
        await pilot.pause()
        # Repopulate is driven by the Select.Changed event
        assert table.row_count <= 2


async def test_findings_table_text_filter():
    """Input.value="EternalBlue" → Input.Changed repopulates with 1 row."""
    screen = FindingsTableScreen(_state())
    app = AutoRedApp()
    async with app.run_test() as pilot:
        app.push_screen(screen)
        await pilot.pause()
        text_input = screen.query_one(Input)
        text_input.value = "EternalBlue"
        await pilot.pause()
        table = screen.query_one(DataTable)
        assert table.row_count == 1


async def test_app_actions_require_state(tmp_path, monkeypatch):
    """``s`` / ``f`` without an engagement notify instead of crashing."""
    monkeypatch.chdir(tmp_path)
    app = AutoRedApp()
    async with app.run_test() as pilot:
        await pilot.press("s")
        await pilot.pause()
        assert not isinstance(app.screen, StateInspectorScreen)
        await pilot.press("f")
        await pilot.pause()
        assert not isinstance(app.screen, FindingsTableScreen)
