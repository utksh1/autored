"""EngagementListScreen tests (Phase 6 Task 13, spec §17.5).

The plan's ``test_list_screen_shows_rows`` originally iterated
``table.rows`` (a Mapping[RowKey, Row]) and asserted substrings
against ``str(k)``. ``RowKey`` is a ``StringKey`` subclass with no
``__str__`` (str yields ``"<RowKey object at 0x…>"``), so the
assertion would never match. The test below uses the documented
``DataTable.get_row_at(index)`` API to read the cell values per row
and asserts against the joined cell text — same intent, working API.
"""
from textual.widgets import DataTable

from autored.models.roe import RulesOfEngagement
from autored.state import EngagementState
from autored.tui.app import AutoRedApp
from autored.tui.screens.dashboard import DashboardScreen
from autored.tui.screens.engagement_list import EngagementListScreen


def _roe() -> RulesOfEngagement:
    return RulesOfEngagement(
        engagement_name="t", operator="t", operator_signature="t",
        allowed_ips=["*"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, data_destruction_allowed=False,
        kernel_exploits_allowed=True, hitl_mode="auto_approve",
    )


def _seed_engagement(tmp_path, engagement_id: str, phase: str) -> None:
    eng_dir = tmp_path / "engagements" / engagement_id
    eng_dir.mkdir(parents=True)
    state = EngagementState(
        engagement_id=engagement_id, target_scope=["10.0.0.5"],
        operator="t", rules_of_engagement=_roe(), phase=phase,
    )
    (eng_dir / "state.json").write_text(state.model_dump_json())


async def test_no_engagement_mounts_list_screen(tmp_path, monkeypatch):
    """No engagement_id, no run_config → EngagementListScreen on mount."""
    monkeypatch.chdir(tmp_path)
    app = AutoRedApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        assert isinstance(app.screen, EngagementListScreen)


async def test_list_screen_shows_rows(tmp_path, monkeypatch):
    """Each seeded engagement folder renders a row with id + phase."""
    monkeypatch.chdir(tmp_path)
    _seed_engagement(tmp_path, "list-e1", "done")
    _seed_engagement(tmp_path, "list-e2", "lateral")

    app = AutoRedApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        table = app.screen.query_one(DataTable)
        # Read each row's cells via the documented get_row_at API
        # (RowKey.__str__ yields "<RowKey object at 0x…>" — substring
        # matching would never work against str(k)).
        all_cells: list[str] = []
        for row_index in range(table.row_count):
            cells = table.get_row_at(row_index)
            all_cells.extend(str(c) for c in cells)
        flat = " ".join(all_cells)
        assert "list-e1" in flat
        assert "list-e2" in flat
        # Phase column reflects the saved state (one row is "done",
        # the other is "lateral").
        assert "done" in flat
        assert "lateral" in flat


async def test_enter_opens_engagement_dashboard(tmp_path, monkeypatch):
    """``enter`` on a selected row opens the engagement's dashboard."""
    monkeypatch.chdir(tmp_path)
    _seed_engagement(tmp_path, "list-e3", "report")

    app = AutoRedApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        table = app.screen.query_one(DataTable)
        # Place the cursor on the first row, first column.
        table.cursor_coordinate = (0, 0)
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, DashboardScreen)
        assert app.engagement_id == "list-e3"
        assert app.current_state is not None
        assert app.current_state.phase == "report"


async def test_global_bindings_present(tmp_path, monkeypatch):
    """Spec §17.6 global keybindings are registered app-wide."""
    monkeypatch.chdir(tmp_path)
    app = AutoRedApp()
    binding_keys = {binding.key for binding in AutoRedApp.BINDINGS}
    for key in ("q", "d", "e", "l", "f", "s", "v", "g", "r", "?"):
        assert key in binding_keys, f"missing global binding: {key}"
