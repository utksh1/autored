"""AgentStatusPanel widget — currently-running agent + step (spec §17.4).

Shows the agent name (recon / vuln / exploit / postex / lateral / cleanup /
report) and the current step within that agent. Empty when no agent is
running.
"""
from __future__ import annotations

from textual.reactive import reactive
from textual.widgets import Static


class AgentStatusPanel(Static):
    """Static widget showing the active agent + current step."""

    DEFAULT_CSS = """
    AgentStatusPanel {
        height: 3;
        padding: 0 1;
        background: $surface;
        border: round $accent;
    }
    """

    agent_name: reactive[str] = reactive[str]("")
    current_step: reactive[str] = reactive[str]("")
    progress: reactive[float] = reactive[float](0.0)

    def set_agent(self, agent_name: str, step: str = "") -> None:
        """Update the active agent + step (called by the EventBus pump)."""
        self.agent_name = agent_name
        self.current_step = step

    def clear(self) -> None:
        """Reset back to idle — no agent running."""
        self.agent_name = ""
        self.current_step = ""
        self.progress = 0.0

    def render(self) -> str:
        if not self.agent_name:
            return "[dim]idle — no agent running[/dim]"
        step_str = f" → {self.current_step}" if self.current_step else ""
        pct = int(self.progress * 100)
        return (
            f"[bold]{self.agent_name}[/bold]{step_str}  [dim]({pct}%)[/dim]"
        )
