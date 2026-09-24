"""ActivityLog widget — scrollable log of tool calls / events (spec §17.4).

Wraps Textual's ``RichLog`` with an ``add_event(event)`` helper that formats
the canonical AutoRed event line:

    [HH:MM:SS] {tool} {target} ({duration:.1f}s) {status}

Status is colour-coded (success=green, error=red, warning=yellow, info=cyan).
"""
from __future__ import annotations

from datetime import datetime

from textual.widgets import RichLog


class ActivityLog(RichLog):
    """Scrollable log of tool-call events from the orchestrator."""

    DEFAULT_CSS = """
    ActivityLog {
        border: round $primary;
        background: $surface;
    }
    """

    MAX_LINES: int = 1000

    STATUS_COLORS: dict[str, str] = {
        "success": "green",
        "error": "red",
        "warning": "yellow",
        "info": "cyan",
        "skipped": "dim",
    }

    def __init__(self, *args, **kwargs) -> None:
        # Hard-cap the buffer at MAX_LINES so long engagements don't OOM the
        # TUI. Callers can still override via explicit ``max_lines=`` kwarg.
        kwargs.setdefault("max_lines", self.MAX_LINES)
        super().__init__(*args, **kwargs)

    def add_event(self, event: dict) -> None:
        """Format a tool-call event and append it to the log.

        Event dict fields:
        - ``tool`` (str)         — e.g. "nmap", "metasploit"
        - ``target`` (str)       — host IP / URL
        - ``status`` (str)       — "success" | "error" | "warning" | "info" | "skipped"
        - ``duration_sec`` (float) — wall-clock time of the tool call
        """
        tool = str(event.get("tool", "?"))
        target = str(event.get("target", "?"))
        status = str(event.get("status", "info"))
        duration = float(event.get("duration_sec", 0.0) or 0.0)
        timestamp = datetime.now().strftime("%H:%M:%S")
        color = self.STATUS_COLORS.get(status, "white")

        line = (
            f"[dim]{timestamp}[/dim] "
            f"[bold]{tool}[/bold] "
            f"[dim]{target}[/dim] "
            f"({duration:.1f}s) "
            f"[{color}]{status}[/{color}]"
        )
        # RichLog.write is safe to call on an unmounted widget (it appends
        # to the internal buffer + schedules a refresh).
        self.write(line)
