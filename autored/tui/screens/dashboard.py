"""DashboardScreen — main engagement dashboard.

Spec reference: §17.4 (DashboardScreen).

Deviation from spec: base class is `Screen` (not `Container`) because
`push_screen` requires a `Screen` subclass. `Container` is a sibling of
`Screen` in the Textual widget hierarchy, so the spec's literal code would
not be pushable.
"""

from __future__ import annotations

from datetime import datetime

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import Footer, Header, ProgressBar, Static

from autored.tui.event_bus import EventBus
from autored.tui.widgets.activity_log import ActivityLog
from autored.tui.widgets.agent_status import AgentStatusPanel
from autored.tui.widgets.phase_indicator import PhaseIndicator


class DashboardScreen(Screen):
    """Main engagement dashboard."""

    CSS = """
    DashboardScreen {
        layout: vertical;
    }
    #top-row {
        height: 3;
    }
    #phase-indicator {
        width: 1fr;
        border: solid $accent;
        padding: 0 1;
    }
    #engagement-info {
        width: 1fr;
        border: solid $accent;
        padding: 0 1;
    }
    #middle-row {
        height: 1fr;
    }
    #agent-panel {
        width: 1fr;
        border: solid $accent;
    }
    #activity-log {
        width: 2fr;
        border: solid $accent;
    }
    #bottom-row {
        height: 3;
    }
    #progress {
        border: solid $accent;
    }
    """

    phase = reactive("recon")
    current_agent = reactive("")
    iteration = reactive(0)

    def __init__(self, engagement_id: str, event_bus: EventBus):
        super().__init__()
        self.engagement_id = engagement_id
        self.event_bus = event_bus

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="top-row"):
            yield PhaseIndicator(id="phase-indicator")
            yield Static(self._engagement_info_text(), id="engagement-info")
        with Horizontal(id="middle-row"):
            yield AgentStatusPanel(id="agent-panel")
            yield ActivityLog(id="activity-log")
        with Horizontal(id="bottom-row"):
            yield ProgressBar(id="progress", total=20)
        yield Footer()

    def on_mount(self) -> None:
        self.title = f"AutoRed — {self.engagement_id}"
        self.set_interval(0.5, self._poll_events)

    def _engagement_info_text(self) -> str:
        return (
            f"Engagement: [bold]{self.engagement_id}[/]\n"
            f"Started: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"
        )

    async def _poll_events(self) -> None:
        """Poll EventBus for events from orchestrator."""
        if self.event_bus is None:
            return
        event = self.event_bus.try_get_tui_event()
        if event is not None:
            await self._handle_event(event)

    async def _handle_event(self, event: dict) -> None:
        etype = event.get("type")
        if etype == "phase_change":
            self.phase = event.get("new_phase", self.phase)
            self.query_one(PhaseIndicator).update_phase(self.phase)
        elif etype == "agent_start":
            self.current_agent = event.get("agent", "")
            self.query_one(AgentStatusPanel).update_agent(event)
        elif etype == "tool_call":
            self.query_one(ActivityLog).add_event(event)
        elif etype == "hitl_gate":
            # Lazy import to avoid circular dependency and to keep Task 10
            # (dashboard) self-contained before Task 11 (HitLGateModal) lands.
            from autored.tui.screens.hitl_gate import HitLGateModal

            self.app.push_screen(HitLGateModal(event), self._handle_hitl_response)
        elif etype == "error":
            self.query_one(ActivityLog).add_error(event)

    def _handle_hitl_response(self, response: dict) -> None:
        """Called when HitL modal is dismissed. Forward response to orchestrator."""
        if self.event_bus is not None:
            self.event_bus.tui_to_orchestrator.put_nowait(response)
