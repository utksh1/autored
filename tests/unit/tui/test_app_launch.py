"""TUI launch integration tests (Phase 6 Task 12).

Spec §14.2: --tui launches the dashboard with the orchestrator running
as a background task; the EventBus carries events between them.

These tests use ``app.run_test()`` Pilot (no real terminal) and mock
the orchestrator's dependencies at the SOURCE module level (the
app's ``_run_orchestrator`` imports everything inside the method
body — patches must target ``autored.graph.build_phase6_graph``,
``autored.persistence.sqlite_saver.make_checkpointer``, etc., NOT
attributes on ``autored.tui.app`` which would raise ``AttributeError``).
"""
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from autored.models.roe import RulesOfEngagement
from autored.state import EngagementState
from autored.tui.app import AutoRedApp, RunConfig
from autored.tui.screens.dashboard import DashboardScreen


def _roe() -> RulesOfEngagement:
    return RulesOfEngagement(
        engagement_name="t", operator="t", operator_signature="t",
        allowed_ips=["*"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, data_destruction_allowed=False,
        kernel_exploits_allowed=True, hitl_mode="auto_approve",
    )


def _final_state_dict() -> dict:
    state = EngagementState(
        engagement_id="tui-e1", target_scope=["10.0.0.5"],
        operator="t", rules_of_engagement=_roe(), phase="done",
    )
    return state.model_dump()


async def test_run_config_starts_orchestrator_and_dashboard(tmp_path, monkeypatch):
    """``RunConfig`` set → ``on_mount`` pushes the dashboard + starts the orchestrator."""
    monkeypatch.chdir(tmp_path)
    fake_graph = MagicMock()
    fake_graph.ainvoke = AsyncMock(return_value=_final_state_dict())

    async def fake_make_checkpointer(engagement_id):
        cp = MagicMock()
        cp.conn = None  # skip the close branch
        return cp

    def fake_load_roe(path):
        return _roe()

    # The app's orchestrator imports everything INSIDE method bodies, so
    # patches must target the SOURCE modules (autored.graph.*, etc.) —
    # patching autored.tui.app.* would raise AttributeError.
    # ``load_roe`` is sync in ``autored.config`` — the fake must be sync
    # too (an ``async def`` fake would return a coroutine object that
    # breaks ``roe_config.operator``).
    with patch("autored.graph.build_phase6_graph", return_value=fake_graph), \
         patch("autored.persistence.sqlite_saver.make_checkpointer",
               fake_make_checkpointer), \
         patch("autored.config.load_roe", fake_load_roe), \
         patch("autored.persistence.filesystem.init_engagement_folder",
               MagicMock()), \
         patch("autored.roe_guard.register_roe", MagicMock()), \
         patch("autored.persistence.filesystem.save_state_to_disk", MagicMock()):
        app = AutoRedApp(run_config=RunConfig(
            target="10.0.0.5", roe_path="roe-sandbox.yaml",
            engagement_id="tui-e1", operator="t",
        ))
        async with app.run_test() as pilot:
            assert isinstance(app.screen, DashboardScreen)
            assert app.orchestrator_task is not None
            await app.orchestrator_task  # deterministic: everything is mocked

    assert app.current_state is not None
    assert app.current_state.phase == "done"
    fake_graph.ainvoke.assert_awaited_once()
    # The orchestrator emitted the completion event on the bus.
    event = app.event_bus.try_get_tui_event()
    assert event is not None
    assert event["type"] == "phase_change"
    assert event["new_phase"] == "done"


async def test_open_engagement_views_saved_state(tmp_path, monkeypatch):
    """``engagement_id`` only → ``_mount_saved_engagement`` (view mode)."""
    monkeypatch.chdir(tmp_path)
    eng_dir = tmp_path / "engagements" / "tui-view-e1"
    eng_dir.mkdir(parents=True)
    state = EngagementState(
        engagement_id="tui-view-e1", target_scope=["10.0.0.5"],
        operator="t", rules_of_engagement=_roe(), phase="lateral",
    )
    (eng_dir / "state.json").write_text(state.model_dump_json())

    app = AutoRedApp(engagement_id="tui-view-e1")
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.current_state is not None
        assert app.current_state.phase == "lateral"
        assert isinstance(app.screen, DashboardScreen)
        assert app.orchestrator_task is None  # view mode — nothing running


async def test_orchestrator_failure_is_surfaced_not_fatal(tmp_path, monkeypatch):
    """A crashed orchestrator must not kill the TUI."""
    monkeypatch.chdir(tmp_path)
    fake_graph = MagicMock()
    fake_graph.ainvoke = AsyncMock(side_effect=RuntimeError("graph exploded"))

    async def fake_make_checkpointer(engagement_id):
        cp = MagicMock()
        cp.conn = None
        return cp

    def fake_load_roe(path):
        return _roe()

    with patch("autored.graph.build_phase6_graph", return_value=fake_graph), \
         patch("autored.persistence.sqlite_saver.make_checkpointer",
               fake_make_checkpointer), \
         patch("autored.config.load_roe", fake_load_roe), \
         patch("autored.persistence.filesystem.init_engagement_folder",
               MagicMock()), \
         patch("autored.roe_guard.register_roe", MagicMock()), \
         patch("autored.persistence.filesystem.save_state_to_disk", MagicMock()):
        app = AutoRedApp(run_config=RunConfig(
            target="10.0.0.5", roe_path="roe.yaml",
            engagement_id="tui-fail-e1", operator="t",
        ))
        async with app.run_test() as pilot:
            await app.orchestrator_task  # completes (error is swallowed + logged)
            await pilot.pause()

    # The app is still alive; an error event went out on the bus.
    events = []
    while (event := app.event_bus.try_get_tui_event()) is not None:
        events.append(event)
    assert any(e["type"] == "error" for e in events)


def test_cli_tui_branch_launches_app():
    """The CLI --tui path must construct AutoRedApp with a RunConfig."""
    source = Path("autored/cli.py").read_text()
    assert "AutoRedApp(" in source
    assert "RunConfig(" in source
    assert ".run()" in source
