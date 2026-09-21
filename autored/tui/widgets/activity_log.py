"""ActivityLog widget — scrolling log of agent activity.

Spec reference: §17.4 (ActivityLog Widget).

Deviation from spec: events are buffered when the widget is not yet
mounted, because Textual's `RichLog.write` requires an active app
(`self.app.console`) to render the renderable. The unit test instantiates
`ActivityLog()` outside of an app context, so we guard the `write` call.
"""

from __future__ import annotations

from datetime import datetime

from rich.text import Text
from textual.widgets import RichLog


class ActivityLog(RichLog):
    """Scrolling log of agent activity."""

    MAX_LINES = 1000

    def __init__(self, **kwargs):
        # RichLog only accepts keyword args; force our preferred defaults
        # unless the caller explicitly overrides them.
        kwargs.setdefault("max_lines", self.MAX_LINES)
        kwargs.setdefault("wrap", True)
        kwargs.setdefault("markup", True)
        super().__init__(**kwargs)
        # Lines buffered while the widget is unmounted (no active app to
        # render through). Flushed on mount.
        self._pending_lines: list = []

    def _emit_line(self, line) -> None:
        """Write a line to the log, buffering if not yet mounted."""
        if self.is_mounted:
            self.write(line)
        else:
            self._pending_lines.append(line)

    def on_mount(self) -> None:
        # Flush any buffered lines from before mount.
        for line in self._pending_lines:
            self.write(line)
        self._pending_lines.clear()

    def add_event(self, event: dict) -> None:
        ts = datetime.utcnow().strftime("%H:%M:%S")
        tool = event.get("tool", "")
        target = event.get("target", "")
        status = event.get("status", "")
        duration = event.get("duration_sec", 0)

        status_color = (
            "green" if status == "success" else "red" if status == "error" else "yellow"
        )
        line = Text(f"[{ts}] ", style="dim")
        line.append(Text(f"{tool} ", style="cyan"))
        line.append(Text(f"{target} ", style="white"))
        line.append(Text(f"({duration:.1f}s) ", style="dim"))
        line.append(Text(status, style=status_color))
        self._emit_line(line)

    def add_error(self, event: dict) -> None:
        ts = datetime.utcnow().strftime("%H:%M:%S")
        line = Text(f"[{ts}] ", style="dim")
        line.append(Text("ERROR: ", style="bold red"))
        line.append(Text(event.get("message", ""), style="red"))
        self._emit_line(line)
