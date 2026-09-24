"""AutoRedApp — main Textual TUI entry point.

Spec reference: §17.4 (App Class), §17.2 (TUI architecture), §14.2
(--tui launches the dashboard with the orchestrator as a background
task on the app's event loop), §17.6 (global keybindings).

Phase 6 additions:

- ``RunConfig`` — a fresh engagement the in-app orchestrator will run,
  constructed by the CLI ``--tui`` branch and consumed by ``on_mount``.
- The background orchestrator task (``orchestrator_task``) running
  ``_run_orchestrator`` as an ``asyncio.create_task`` on the app loop —
  Pilot can ``await`` it directly for deterministic test completion,
  and the EventBus queues are shared without cross-thread sync.
- ``current_state`` — the live ``EngagementState`` consumed by the
  Phase 6 screens (Tasks 14–16).
- ``open_engagement`` — load a saved engagement (view / resume) from
  the EngagementListScreen.
- §17.6 global keybindings: ``q``/``d``/``e``/``l``/``f``/``s``/``v``/
  ``g``/``r``/``h``/``?`` — the screens that ship in this task have
  real pushes; the screens that ship in T14–T17 register their
  bindings now with stub actions ("screen ships in Task N") that the
  later task replaces.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

from textual.app import App
from textual.binding import Binding

from autored.logging import get_logger
from autored.tui.event_bus import EventBus
from autored.tui.screens.dashboard import DashboardScreen
from autored.tui.screens.help import HelpScreen

log = get_logger("tui.app")


@dataclass
class RunConfig:
    """A fresh engagement for the in-app orchestrator to run.

    Built by the CLI ``--tui`` branch from the parsed ``--target`` /
    ``--roe`` options and the minted engagement id. Consumed by
    ``AutoRedApp._mount_fresh_engagement`` on ``on_mount``.
    """

    target: str
    roe_path: str
    engagement_id: str
    operator: str


class AutoRedApp(App):
    """AutoRed TUI — red team copilot interface."""

    CSS_PATH = "app.tcss"
    TITLE = "AutoRed"
    SUB_TITLE = "Red Team Copilot"

    # Spec §17.6 global keybindings. The screens that need constructor
    # args (Logs/Findings/State/Evidence/AttackGraph/RoE editor) cannot
    # be string-pushed via ``push_screen('name')`` because Textual's
    # installed-screens dict does not support per-push args — so those
    # bindings dispatch to ``action_*`` methods that instantiate the
    # screen with the engagement id / event bus / state. Tasks 14–17
    # replace each stub action with the real screen push.
    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("d", "show_dashboard", "Dashboard", show=True),
        Binding("e", "show_engagements", "Engagements", show=True),
        Binding("l", "show_logs", "Logs", show=True),
        Binding("f", "show_findings", "Findings", show=True),
        Binding("s", "show_state_inspector", "State", show=True),
        Binding("v", "show_evidence", "Evidence", show=True),
        Binding("g", "show_attack_graph", "Attack graph", show=True),
        Binding("r", "show_roe_editor", "RoE editor", show=True),
        Binding("h", "push_screen('help')", "Help", show=True),
        Binding("?", "push_screen('help')", "Help", show=False),
    ]

    # HelpScreen takes no constructor args, so we can register it via
    # the ``SCREENS`` mapping and string-push it from the ``h`` / ``?``
    # bindings. Screens taking engagement_id/event_bus/state are
    # instantiated directly inside their ``action_*`` handlers.
    SCREENS = {"help": HelpScreen}

    def __init__(
        self,
        engagement_id: str | None = None,
        run_config: RunConfig | None = None,
    ) -> None:
        super().__init__()
        self.engagement_id = engagement_id
        self.run_config = run_config
        # EventBus bridges orchestrator ↔ TUI via two asyncio queues.
        # The orchestrator pushes events to ``orchestrator_to_tui``; the
        # TUI pumps them into widget updates (Phase 3 wiring lives in
        # ``DashboardScreen``; Tasks 14–16 add the per-screen pumps).
        self.event_bus = EventBus()
        # ``current_state`` is the live ``EngagementState`` the Phase 6
        # screens read from. ``None`` until the orchestrator produces
        # its first snapshot or a saved engagement is loaded.
        self.current_state = None
        # The background LangGraph run — ``asyncio.create_task`` on the
        # app loop, awaited directly by tests via ``await
        # app.orchestrator_task`` for deterministic completion.
        self.orchestrator_task: asyncio.Task | None = None

    # ------------------------------------------------------------------ #
    # Orchestrator — runs as a background task on the app's event loop
    # ------------------------------------------------------------------ #

    async def _run_orchestrator(self, state) -> None:
        """Run the Phase 6 graph; emit phase_change / error events.

        Spec §14.2 ("Orchestrator runs in background thread/task"):
        the graph runs as an ``asyncio.Task`` on the app loop so the
        EventBus queues are shared without cross-thread synchronisation
        and Pilot can ``await`` the task directly in tests.

        Imports live inside the method body so the test patches can
        target the SOURCE modules (``autored.graph.build_phase6_graph``,
        ``autored.persistence.sqlite_saver.make_checkpointer``, etc.)
        rather than attributes on ``autored.tui.app`` (which never
        exist at module level — function-local imports are the SDD
        patch pattern used by the Phase 6 CLI tests too).
        """
        from autored.graph import build_phase6_graph
        from autored.persistence.filesystem import save_state_to_disk
        from autored.persistence.sqlite_saver import make_checkpointer
        from autored.roe_guard import register_roe

        engagement_id = state.engagement_id
        register_roe(engagement_id, state.rules_of_engagement)
        state.event_bus = self.event_bus

        log.info("tui_orchestrator_start", engagement_id=engagement_id)
        checkpointer = await make_checkpointer(engagement_id)
        try:
            graph = build_phase6_graph(checkpointer)
            # I1 (Phase 3 fix wave, carried into Phase 6): the EventBus
            # travels via ``RunnableConfig.configurable`` rather than a
            # non-Pydantic state attribute — LangGraph's reducer strips
            # ``__pydantic_extra__`` (where ``state.event_bus`` lived
            # under ``extra="allow"``), so the previous ``state.event_bus
            # = bus`` pattern silently lost the bus between CLI and the
            # exploit_node. The config dict is the standard LangGraph
            # channel for runtime objects (handles, queues, connections)
            # and bypasses the reducer boundary. Both ``state.event_bus``
            # (for in-method access) and ``config["configurable"]
            # ["event_bus"]`` (for cross-node access) are set here.
            config = {
                "configurable": {
                    "thread_id": engagement_id,
                    "event_bus": self.event_bus,
                }
            }
            final_state = await graph.ainvoke(state, config=config)
            if isinstance(final_state, dict):
                from autored.state import EngagementState

                final_state = EngagementState.model_validate(final_state)
            self.current_state = final_state
            save_state_to_disk(engagement_id, final_state)
            await self.event_bus.emit_to_tui({
                "type": "phase_change",
                "new_phase": final_state.phase,
            })
            log.info(
                "tui_orchestrator_done",
                engagement_id=engagement_id,
                phase=final_state.phase,
            )
        except asyncio.CancelledError:
            log.info("tui_orchestrator_cancelled", engagement_id=engagement_id)
            raise
        except Exception as e:  # noqa: BLE001 — the TUI must survive a crash
            log.error(
                "tui_orchestrator_failed",
                engagement_id=engagement_id,
                error=str(e),
            )
            await self.event_bus.emit_to_tui({
                "type": "error",
                "category": "state",
                "message": f"orchestrator failed: {e}",
                "agent": "orchestrator",
            })
        finally:
            conn = getattr(checkpointer, "conn", None)
            if conn is not None:
                try:
                    close_result = conn.close()
                    if asyncio.iscoroutine(close_result):
                        await close_result
                except Exception:  # noqa: BLE001 — best-effort close
                    pass

    async def _start_orchestrator(self, state) -> None:
        """Schedule ``_run_orchestrator`` as a background task on the app loop."""
        self.orchestrator_task = asyncio.create_task(self._run_orchestrator(state))

    # ------------------------------------------------------------------ #
    # Engagement opening (view / resume)
    # ------------------------------------------------------------------ #

    async def open_engagement(
        self, engagement_id: str, resume: bool = False
    ) -> None:
        """Load a saved engagement and show its dashboard.

        Spec §17.5: ``enter`` from the EngagementListScreen opens in
        view mode (``resume=False``) — only the saved state is loaded
        and the dashboard rendered; ``r`` opens in resume mode
        (``resume=True``) — the orchestrator is started from the
        loaded state so it continues the engagement from its last
        checkpoint via the engagement's ``state.db``.
        """
        from autored.persistence.filesystem import load_state_from_disk

        state = load_state_from_disk(engagement_id)
        if state is None:
            self.notify(f"No saved state for {engagement_id}", severity="error")
            return
        self.current_state = state
        self.engagement_id = engagement_id
        # Pop the EngagementListScreen off the stack before pushing the
        # dashboard so the operator's ``d`` / ``e`` keybindings swap
        # screens rather than stack them. ``pop_screen`` is safe — the
        # default screen stack always has at least one screen on it
        # (the EngagementListScreen itself).
        self.pop_screen()
        self.push_screen(DashboardScreen(engagement_id, self.event_bus))
        if resume:
            await self._start_orchestrator(state)

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    def on_mount(self) -> None:
        """Branch on how the app was constructed.

        - ``run_config`` set → fresh engagement: build state, push
          dashboard, start the orchestrator as a background task.
        - ``engagement_id`` only → view a saved engagement: load the
          saved state (if any) and push the dashboard; no orchestrator.
        - Neither → EngagementListScreen (Task 13) so the operator can
          pick a past engagement to view / resume.
        """
        if self.run_config is not None:
            self._mount_fresh_engagement()
        elif self.engagement_id:
            self._mount_saved_engagement(self.engagement_id)
        else:
            from autored.tui.screens.engagement_list import EngagementListScreen

            self.push_screen(EngagementListScreen())

    def _mount_fresh_engagement(self) -> None:
        from autored.config import load_roe
        from autored.persistence.filesystem import init_engagement_folder
        from autored.state import EngagementState

        roe_config = load_roe(self.run_config.roe_path)
        init_engagement_folder(
            self.run_config.engagement_id,
            self.run_config.target,
            roe_config.operator,
        )
        state = EngagementState(
            engagement_id=self.run_config.engagement_id,
            target_scope=[self.run_config.target],
            operator=roe_config.operator,
            rules_of_engagement=roe_config,
        )
        self.engagement_id = self.run_config.engagement_id
        self.current_state = state
        self.push_screen(DashboardScreen(self.engagement_id, self.event_bus))
        # Fire-and-forget on the app loop; tests await the task directly
        # for deterministic completion. ``asyncio.create_task`` (rather
        # than ``self._start_orchestrator``) because ``on_mount`` is
        # synchronous and can't ``await`` — the helper exists for
        # ``open_engagement(resume=True)`` which IS async.
        self.orchestrator_task = asyncio.create_task(self._run_orchestrator(state))

    def _mount_saved_engagement(self, engagement_id: str) -> None:
        from autored.persistence.filesystem import load_state_from_disk

        state = load_state_from_disk(engagement_id)
        if state is not None:
            self.current_state = state
        self.push_screen(DashboardScreen(engagement_id, self.event_bus))

    # ------------------------------------------------------------------ #
    # Global actions — spec §17.6 keybindings
    # ------------------------------------------------------------------ #

    async def action_quit(self) -> None:
        """``q`` — cancel a running orchestrator task before exiting.

        Without cancellation the background ``ainvoke`` keeps the
        checkpointer's SQLite connection open after the app exits,
        leaking a file handle; cancelling lets the ``finally`` block
        in ``_run_orchestrator`` close it cleanly. The ``except``
        swallows ``CancelledError`` (the expected outcome of cancel)
        and any other exception (the orchestrator might already have
        completed or crashed before ``q`` was pressed).
        """
        if self.orchestrator_task is not None and not self.orchestrator_task.done():
            self.orchestrator_task.cancel()
            try:
                await self.orchestrator_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        self.exit()

    async def action_show_dashboard(self) -> None:
        """``d`` — push the dashboard for the current engagement.

        Idempotent: if the dashboard is already the active screen, do
        nothing (avoids stacking two dashboards on ``d`` spam).
        """
        if self.engagement_id and not isinstance(self.screen, DashboardScreen):
            self.pop_screen()
            self.push_screen(DashboardScreen(self.engagement_id, self.event_bus))

    async def action_show_engagements(self) -> None:
        """``e`` — push the EngagementListScreen (browse past engagements)."""
        from autored.tui.screens.engagement_list import EngagementListScreen

        if not isinstance(self.screen, EngagementListScreen):
            self.pop_screen()
            self.push_screen(EngagementListScreen())

    async def action_show_logs(self) -> None:
        """``l`` — push the LogViewerScreen (tail the operational log).

        Imports the screen inside the method body so the spec §17.6
        keymap is registered from Phase 6 Task 13 onward even before
        Task 14 ships (function-local import keeps the runtime light
        when the operator never opens the viewer).
        """
        from autored.tui.screens.log_viewer import LogViewerScreen

        self.pop_screen()
        self.push_screen(LogViewerScreen())

    async def action_show_findings(self) -> None:
        """``f`` — push the FindingsTableScreen (sortable findings table).

        Notifies "open an engagement first" when ``current_state`` is
        None — the table has nothing to render without a loaded state
        (no vulnerabilities to list).
        """
        if self.current_state is None:
            self.notify(
                "Open an engagement first (e → list, enter)",
                severity="warning",
            )
            return
        from autored.tui.screens.findings_table import FindingsTableScreen

        self.pop_screen()
        self.push_screen(FindingsTableScreen(self.current_state))

    async def action_show_state_inspector(self) -> None:
        """``s`` — push the StateInspectorScreen (browse EngagementState).

        Notifies "open an engagement first" when ``current_state`` is
        None — the tree has nothing to render without a loaded state.
        """
        if self.current_state is None:
            self.notify(
                "Open an engagement first (e → list, enter)",
                severity="warning",
            )
            return
        from autored.tui.screens.state_inspector import StateInspectorScreen

        self.pop_screen()
        self.push_screen(StateInspectorScreen(self.current_state))

    async def action_show_evidence(self) -> None:
        """``v`` — push the EvidenceViewerScreen (captured evidence tabs).

        Notifies "open an engagement first" when ``engagement_id`` is
        unset — the viewer reads ``engagements/<id>/evidence/`` so an
        unset id has nothing to display.
        """
        if not self.engagement_id:
            self.notify(
                "Open an engagement first (e → list, enter)",
                severity="warning",
            )
            return
        from autored.tui.screens.evidence_viewer import EvidenceViewerScreen

        self.pop_screen()
        self.push_screen(EvidenceViewerScreen(self.engagement_id))

    async def action_show_attack_graph(self) -> None:
        """``g`` — push the AttackGraphScreen (Rich Tree of pivot paths).

        Notifies "open an engagement first" when ``current_state`` is
        None — the tree has nothing to render without a loaded state
        (no footholds or pivots to draw).
        """
        if self.current_state is None:
            self.notify(
                "Open an engagement first (e → list, enter)",
                severity="warning",
            )
            return
        from autored.tui.screens.attack_graph import AttackGraphScreen

        self.pop_screen()
        self.push_screen(AttackGraphScreen(self.current_state))

    async def action_show_roe_editor(self) -> None:
        """``r`` — push the RoEEditorScreen (view/edit ``roe-sandbox.yaml``).

        The spec's per-engagement RoE is immutable once an engagement
        starts; editing the file affects only the next engagement
        (which the screen's header states explicitly). The sandbox
        file is the operator's active editable RoE — pushed here so
        ``r`` is always wired to a real file path.
        """
        from autored.tui.screens.roe_editor import RoEEditorScreen

        self.pop_screen()
        self.push_screen(RoEEditorScreen("roe-sandbox.yaml"))
