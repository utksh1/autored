"""LogViewerScreen — tail the operational log in real time (spec §17.5).

Reads ``logs/YYYY-MM-DD.jsonl`` (spec §11.2 stream) every second. Lines
are truncated at 500 characters so a single huge JSON event cannot break
the layout. ``f`` toggles follow-tail (auto-scroll to end).

Phase 6 Task 14 adaptation notes:

- The plan was authored against Textual 0.79's ``RichLog.line_count``
  property, which was removed when Textual switched to a
  ``list[Strip]`` backing store. The actual counter is now
  ``len(RichLog.lines)``; the test was adapted to use that accessor
  rather than the removed property.

- ``RichLog.write_line`` was deprecated and removed in Textual 0.46+;
  the plan already uses ``write()`` (the documented API).

- The screen inherits from ``Screen`` (not ``Container`` — Textual
  requires ``Screen`` for ``push_screen`` routing).
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import Footer, Header, RichLog

# 500 chars per line keeps a single huge JSON event from wrapping the
# layout (Textual's ``RichLog`` wraps by default with ``wrap=True``;
# ``wrap=False`` truncates the visible region but the stored Strip still
# keeps the full text — capping at write time bounds the Strip length).
MAX_LINE_CHARS = 500
# 2000 lines is ~5 minutes of nmap verbose output at 5 lines/sec — a
# reasonable tail buffer for an operator scrolling back to compare
# tool calls. Older lines fall off the top.
MAX_TAIL_LINES = 2000


class LogViewerScreen(Screen):
    """Tail the operational log in real time."""

    BINDINGS = [
        Binding("f", "toggle_follow", "Follow", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        # ``follow`` toggles ``RichLog.auto_scroll`` — when off, the
        # viewport stays at the operator's current scroll position even
        # as new lines append (so they can compare two tool calls
        # without the tail yanking them to the bottom).
        self.follow = True
        # Tracks the count of lines already rendered so each ``_refresh``
        # only appends the new tail (incremental append) rather than
        # re-reading the whole file. Reset only on screen mount.
        self._rendered_lines = 0

    def compose(self) -> ComposeResult:
        yield Header()
        yield RichLog(
            id="log-tail",
            max_lines=MAX_TAIL_LINES,
            wrap=False,
            markup=True,
        )
        yield Footer()

    def on_mount(self) -> None:
        self.title = "AutoRed — Operational Log"
        # Seed the initial render immediately so the operator (and
        # tests) see today's log the moment the screen mounts, then
        # continue polling on the 1-second interval for live updates.
        self._refresh()
        self.set_interval(1.0, self._refresh)

    def _log_path(self) -> Path:
        """Today's operational log path: ``logs/YYYY-MM-DD.jsonl``.

        Spec §11.2 mandates one JSONL file per UTC day so engagements
        spanning midnight naturally rotate. ``datetime.utcnow`` matches
        the writer's date function (``autored.logging.get_logger``).
        """
        return Path("logs") / f"{datetime.utcnow().strftime('%Y-%m-%d')}.jsonl"

    def _refresh(self) -> None:
        """Append new log lines to the ``RichLog`` widget.

        Idempotent on ``_rendered_lines``: reads the current file, slices
        off already-rendered lines, and writes only the new ones. If the
        file doesn't exist yet (no log dir for a fresh engagement), an
        explicit "no log yet" message is written once so the operator
        isn't staring at a blank viewport wondering if the screen is
        broken. Lines are truncated to ``MAX_LINE_CHARS`` (500) at write
        time so a single JSON event with a multi-KB blob field can't
        blow up the layout.
        """
        log_widget = self.query_one(RichLog)
        log_path = self._log_path()
        if not log_path.exists():
            # Only show the "no log yet" hint once per session — repeated
            # refreshes would otherwise stack the same dim line at 1Hz.
            if self._rendered_lines == 0:
                log_widget.write(
                    f"[dim]No operational log at {log_path} (yet).[/]"
                )
                self._rendered_lines = 1
            return
        lines = log_path.read_text(errors="ignore").splitlines()
        # Slice off already-rendered lines so the second-and-later
        # refreshes only append the new tail. If the file was rotated
        # (shorter than last refresh), ``max(0, ...)`` clamps to a full
        # re-read rather than a negative slice.
        if len(lines) < self._rendered_lines:
            # Log rotated/truncated since the last refresh — re-render
            # from the start.
            new_lines = lines
        else:
            new_lines = lines[self._rendered_lines:]
        for line in new_lines:
            log_widget.write(line[:MAX_LINE_CHARS])
        self._rendered_lines = len(lines)

    def action_toggle_follow(self) -> None:
        """``f`` — toggle follow-tail (auto-scroll to end on new lines)."""
        self.follow = not self.follow
        log_widget = self.query_one(RichLog)
        log_widget.auto_scroll = self.follow
        self.app.notify(f"Follow tail: {'on' if self.follow else 'off'}")
