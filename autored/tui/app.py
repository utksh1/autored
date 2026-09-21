"""AutoRedApp — main Textual TUI entry point.

Spec reference: §17.4 (App Class).
"""

from __future__ import annotations

from textual.app import App
from textual.binding import Binding

from autored.tui.event_bus import EventBus
from autored.tui.screens.dashboard import DashboardScreen
from autored.tui.screens.help import HelpScreen


class AutoRedApp(App):
    """AutoRed TUI — red team copilot interface."""

    CSS_PATH = "app.tcss"
    TITLE = "AutoRed"
    SUB_TITLE = "Red Team Copilot"

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("d", "push_screen('dashboard')", "Dashboard", show=True),
        Binding("h", "push_screen('help')", "Help", show=True),
        Binding("?", "push_screen('help')", "Help", show=False),
    ]

    SCREENS = {
        "dashboard": DashboardScreen,
        "help": HelpScreen,
    }

    def __init__(self, engagement_id: str | None = None):
        super().__init__()
        self.engagement_id = engagement_id
        # EventBus bridges orchestrator ↔ TUI via two asyncio queues.
        self.event_bus = EventBus()

    def on_mount(self) -> None:
        if self.engagement_id:
            self.push_screen(DashboardScreen(self.engagement_id, self.event_bus))
        else:
            # No engagement selected — show dashboard with placeholder id.
            self.push_screen(DashboardScreen("none", self.event_bus))
