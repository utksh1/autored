"""AgentStatusPanel widget — shows current agent status.

Spec reference: §17.4 (AgentStatusPanel Widget).
"""

from __future__ import annotations

from datetime import datetime

from textual.reactive import reactive
from textual.widgets import Static


class AgentStatusPanel(Static):
    """Shows current agent name, what it's doing, how long."""

    agent_name = reactive("")
    task_description = reactive("")
    started_at = reactive(None)
    tool_calls = reactive(0)
    llm_calls = reactive(0)

    def render(self) -> str:
        if not self.agent_name:
            return "[dim]No active agent[/]"

        elapsed = ""
        if self.started_at:
            delta = datetime.utcnow() - self.started_at
            elapsed = f"{delta.seconds // 60}:{delta.seconds % 60:02d}"

        return (
            f"[bold cyan]{self.agent_name.upper()}[/] Agent\n"
            f"\n"
            f"Task: {self.task_description}\n"
            f"Elapsed: {elapsed}\n"
            f"Tool calls: {self.tool_calls}\n"
            f"LLM calls: {self.llm_calls}\n"
        )

    def update_agent(self, event: dict) -> None:
        self.agent_name = event["agent"]
        self.task_description = event.get("task", "")
        started = event.get("started_at")
        if started:
            try:
                self.started_at = datetime.fromisoformat(started)
            except (ValueError, TypeError):
                self.started_at = None
        else:
            self.started_at = None
        # Reset counters on new agent
        self.tool_calls = 0
        self.llm_calls = 0
