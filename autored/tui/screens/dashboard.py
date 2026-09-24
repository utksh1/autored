"""DashboardScreen — the main engagement dashboard (spec §17.4).

Composes the PhaseIndicator, AgentStatusPanel, and ActivityLog widgets into
a single vertical layout. This is the default screen AutoRedApp pushes on
mount.

Phase 6 (Task 12): the constructor now accepts ``engagement_id`` and
``event_bus`` so the dashboard can display engagement context and pump
orchestrator events from the bus (the pump wiring ships in Task 14's
LogViewerScreen; the args land here so ``AutoRedApp._mount_*_engagement``
can pass them today). Both args default to ``None`` so backward-compat
with Phase 3's no-arg instantiation (``DashboardScreen()``) is preserved.
"""
from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen

from autored.tui.widgets.activity_log import ActivityLog
from autored.tui.widgets.agent_status import AgentStatusPanel
from autored.tui.widgets.phase_indicator import PhaseIndicator


class DashboardScreen(Screen):
    """Main dashboard — phase indicator + agent status + activity log."""

    DEFAULT_CSS = """
    DashboardScreen {
        layout: vertical;
    }
    #dashboard-body {
        height: 1fr;
    }
    """

    def __init__(
        self,
        engagement_id: str | None = None,
        event_bus=None,
    ) -> None:
        super().__init__()
        self.engagement_id = engagement_id
        self.event_bus = event_bus

    def compose(self) -> ComposeResult:
        yield PhaseIndicator()
        yield AgentStatusPanel()
        yield Vertical(ActivityLog(), id="dashboard-body")
