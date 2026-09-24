"""FindingsTableScreen — sortable, filterable findings table (spec §17.5).

Severity ``Select`` + text ``Input`` filters over a ``DataTable`` (Host,
Port, Service, CVE, Severity, Title, Discovered). ``s`` re-sorts rows
by severity (critical first); ``f`` focuses the text filter; ``e``
notifies the operator to press ``v`` for the full evidence viewer.

Phase 6 Task 15 adaptation: the screen inherits from ``Screen`` (not
``Container`` — Textual requires ``Screen`` for ``push_screen`` routing).
"""
from __future__ import annotations

from typing import Any

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Input, Select

# Severity ordering for the ``s`` (sort by severity) binding — critical
# first, info last. Unknown severities sort to the end (99).
SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


class FindingsTableScreen(Screen):
    """Sortable, filterable table of all findings.

    Takes a live ``EngagementState`` so ``s`` (sort) can mutate the
    state's ``vulnerabilities`` list in place — the next time the
    dashboard or report agent reads the state, the rows come out in
    severity order (the operator's sort preference is sticky for the
    engagement lifetime).
    """

    BINDINGS = [
        Binding("s", "sort_by_severity", "Sort", show=True),
        Binding("f", "focus_filter", "Filter", show=True),
        Binding("e", "view_evidence", "Evidence", show=True),
    ]

    def __init__(self, state: Any) -> None:
        super().__init__()
        self.state = state

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="filters"):
            yield Select(
                [
                    ("All", "all"),
                    ("Critical", "critical"),
                    ("High", "high"),
                    ("Medium", "medium"),
                    ("Low", "low"),
                    ("Info", "info"),
                ],
                id="severity-filter",
                value="all",
            )
            yield Input(placeholder="Filter by text...", id="text-filter")
        yield DataTable(id="findings-table")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "AutoRed — Findings"
        table = self.query_one(DataTable)
        # Spec §17.5 column set — Host / Port / Service / CVE /
        # Severity / Title / Discovered. Discovered is just HH:MM so
        # the column doesn't dominate the table; the full timestamp
        # lives in the row tooltip (via ``DataTable.add_row(key=...)``)
        # or the evidence viewer (``v``).
        table.add_columns(
            "Host", "Port", "Service", "CVE", "Severity",
            "Title", "Discovered",
        )
        table.cursor_type = "row"
        self._populate()

    def _populate(self) -> None:
        """Re-populate the table from ``state.vulnerabilities``.

        Filters are read live from the ``Select`` (severity) and ``Input``
        (text) widgets so any filter change immediately re-renders. The
        ``text_filter`` is matched case-insensitively against a
        concatenation of ``title + description + cve + service`` so the
        operator can search "EternalBlue" or "smb" interchangeably.
        """
        table = self.query_one(DataTable)
        table.clear()
        severity_filter = self.query_one("#severity-filter", Select).value
        text_filter = (
            self.query_one("#text-filter", Input).value.lower()
        )

        for vuln in self.state.vulnerabilities:
            if severity_filter != "all" and vuln.severity != severity_filter:
                continue
            haystack = " ".join(
                filter(
                    None,
                    (
                        vuln.title,
                        vuln.description,
                        vuln.cve or "",
                        vuln.service or "",
                    ),
                )
            ).lower()
            if text_filter and text_filter not in haystack:
                continue
            table.add_row(
                vuln.host_ip,
                str(vuln.port or ""),
                vuln.service or "",
                vuln.cve or "",
                vuln.severity,
                vuln.title[:60],
                vuln.discovered_at.strftime("%H:%M"),
            )

    @on(Select.Changed, "#severity-filter")
    @on(Input.Changed, "#text-filter")
    def _on_filter_change(self, event: Any) -> None:
        """Re-populate the table on any filter change.

        ``@on(Select.Changed, "#severity-filter")`` and the parallel
        ``Input.Changed`` decorator route both messages through the
        same handler so we don't duplicate the re-populate call.
        """
        self._populate()

    def action_sort_by_severity(self) -> None:
        """``s`` — re-sort the state's ``vulnerabilities`` by severity.

        Sort is in-place so the preference is sticky for the engagement
        lifetime (next dashboard refresh, next report run, etc. all see
        critical first). A notify confirms the action so the operator
        knows the table updated (the rows visibly re-order but the
        notify is the explicit signal that ``s`` ran, not just a layout
        refresh).
        """
        vulns = sorted(
            self.state.vulnerabilities,
            key=lambda v: SEVERITY_ORDER.get(v.severity, 99),
        )
        self.state.vulnerabilities = vulns
        self._populate()
        self.app.notify("Sorted by severity (critical first)")

    def action_focus_filter(self) -> None:
        """``f`` — focus the text filter input so the operator can type."""
        self.query_one("#text-filter", Input).focus()

    def action_view_evidence(self) -> None:
        """``e`` — point the operator to the evidence viewer.

        The table row's evidence path is shown in the row tooltip (added
        when the row is built — TBD in Task 16's attack-graph polish);
        this binding is a hint that ``v`` is the global shortcut to
        open the full evidence viewer rather than a per-row push.
        """
        self.app.notify(
            "Press v for the full evidence viewer", severity="information"
        )
