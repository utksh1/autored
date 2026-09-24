"""EngagementListScreen — browse past engagements (spec §17.5).

Rows come from the filesystem scan (always present, even before the
first cross-engagement DB write) enriched with phase/counts from each
engagement's saved ``state.json`` (best-effort — a corrupt state shows
a ``"?"`` phase rather than breaking the screen).

The screen deliberately reads from ``engagements/<id>/state.json``
rather than the SQLite cross-engagement memory store (``db/engagements
.sqlite``) so the list works before any DB write — fresh CI runs that
seed a state file via ``save_state_to_disk`` see rows immediately,
without booting ``init_db``.
"""
from __future__ import annotations

import json
from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header


def _load_rows() -> list[dict]:
    """One row per engagement folder: id, target, phase, started, findings.

    Returns a list of plain dicts (one per engagement folder under
    ``engagements/``). Reads each ``state.json`` (best-effort —
    corrupt JSON or missing fields surface as ``"?"`` / ``"—"``
    placeholders rather than raising so a single broken engagement
    folder never blanks the whole list).
    """
    rows: list[dict] = []
    engagements_dir = Path("engagements")
    if not engagements_dir.exists():
        return rows
    for eng_dir in sorted(engagements_dir.iterdir()):
        if not eng_dir.is_dir():
            continue
        state_path = eng_dir / "state.json"
        phase, findings, footholds, started, target = (
            "?", "—", "—", "—", "—",
        )
        data: dict | None = None
        if state_path.exists():
            try:
                data = json.loads(state_path.read_text())
                phase = data.get("phase", "?") or "?"
                findings = str(len(data.get("vulnerabilities", []) or []))
                footholds = str(len(data.get("footholds", []) or []))
                started = (
                    (data.get("started_at") or "—")[:16].replace("T", " ")
                    if data.get("started_at")
                    else "—"
                )
                target = ", ".join(data.get("target_scope", []) or [])
                if not target:
                    target = "—"
            except (json.JSONDecodeError, OSError):
                # Corrupt state — show placeholders, never crash the
                # screen. ``data`` stays ``None`` so the ``target`` field
                # below falls through to the placeholder.
                pass
        rows.append({
            "id": eng_dir.name,
            "target": target if data is not None else "—",
            "phase": phase,
            "started": started,
            "findings": findings,
            "footholds": footholds,
        })
    return rows


class EngagementListScreen(Screen):
    """Browse past engagements.

    DataTable columns (spec §17.5): ID, Target, Phase, Started,
    Findings, Footholds. Keybindings: ``enter`` opens the selected
    engagement in view mode, ``R`` (shift+r) resumes it, ``d`` deletes
    (disabled in Phase 6 — engagement folders are the audit record,
    so the binding is documented but not wired to a destructive
    action), ``n`` starts a new engagement (delegated to the CLI —
    spawning the wizard from inside the TUI is out of Phase 6 scope).

    Phase 6 Task 17 adaptation: the per-screen ``r`` (resume) binding
    was renamed to ``R`` (capital) so the spec §17.6 global ``r`` =
    RoE editor isn't shadowed when EngagementListScreen is the active
    screen (Textual's binding precedence is screen > app, so the
    screen-level ``r`` would have swallowed the global one).
    """

    BINDINGS = [
        Binding("enter", "open_engagement", "Open", show=True),
        Binding("R", "resume_engagement", "Resume", show=True),
        Binding("d", "delete_engagement", "Delete", show=True),
        Binding("n", "new_engagement", "New", show=True),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield DataTable(id="engagement-table")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "AutoRed — Engagements"
        table = self.query_one(DataTable)
        # ``cursor_type="row"`` so pressing ``enter`` posts a
        # ``RowSelected`` message we can listen for (cell-mode posts
        # ``CellSelected`` instead). Row-mode is also more user-friendly
        # for a single-selection list (up/down moves the whole row
        # highlight rather than a per-cell cursor).
        table.cursor_type = "row"
        table.add_columns(
            "ID", "Target", "Phase", "Started", "Findings", "Footholds",
        )
        for row in _load_rows():
            # ``key=row["id"]`` makes the row's identity stable across
            # re-renders and lets ``RowSelected.row_key.value`` be the
            # engagement id we need for ``open_engagement``.
            table.add_row(
                row["id"], row["target"], row["phase"], row["started"],
                row["findings"], row["footholds"],
                key=row["id"],
            )

    async def on_data_table_row_selected(
        self, event: DataTable.RowSelected
    ) -> None:
        """``enter`` on a row → open the engagement in view mode.

        Textual's ``DataTable`` consumes the ``enter`` keystroke for its
        own ``select_cursor`` action (which posts this message), so a
        screen-level ``Binding("enter", "open_engagement", ...)`` never
        fires. Listening for the message is the documented pattern.
        """
        row_key_value = getattr(event.row_key, "value", None)
        if not row_key_value or row_key_value == "None":
            return
        engagement_id = str(row_key_value)
        await self.app.open_engagement(engagement_id, resume=False)

    def _selected_engagement_id(self) -> str | None:
        """Read the ID column of the row under the cursor.

        Returns ``None`` when the table is empty (no rows to select)
        or when the cursor is on a stale coordinate (e.g., the table
        was just cleared). Used by the ``r`` (resume) and ``d``
        (delete) bindings — ``enter`` goes through
        ``on_data_table_row_selected`` instead (the row_key already
        identifies the engagement, no need to re-read it from the
        cursor coordinate).
        """
        table = self.query_one(DataTable)
        if table.row_count == 0:
            return None
        coordinate = table.cursor_coordinate
        if coordinate.row is None or coordinate.row < 0:
            return None
        try:
            row_values = table.get_row_at(coordinate.row)
        except Exception:  # noqa: BLE001 — empty table / stale coordinate
            return None
        if not row_values:
            return None
        return str(row_values[0])

    async def action_open_engagement(self) -> None:
        """``enter`` fallback (also bound on the screen).

        Textual's ``DataTable`` consumes ``enter`` for ``select_cursor``,
        so this handler rarely fires — the
        ``on_data_table_row_selected`` path above is the one that runs.
        Kept for the screen-binding footer display and as a defensive
        fallback if ``DataTable`` ever stops consuming the keystroke.
        """
        engagement_id = self._selected_engagement_id()
        if engagement_id:
            await self.app.open_engagement(engagement_id, resume=False)

    async def action_resume_engagement(self) -> None:
        """``r`` — resume the selected engagement (orchestrator restart)."""
        engagement_id = self._selected_engagement_id()
        if engagement_id:
            await self.app.open_engagement(engagement_id, resume=True)

    def action_delete_engagement(self) -> None:
        # Reserved key (spec §17.5 lists the binding; deletion semantics
        # are deliberately out of Phase 6 scope — engagement folders
        # are the audit record and ``roe_audit`` trail, so we warn and
        # no-op rather than risk a destructive delete).
        self.app.notify(
            "Deletion is disabled — engagement folders are the audit record.",
            severity="warning",
        )

    def action_new_engagement(self) -> None:
        """``n`` — start a new engagement.

        Delegated to the CLI because spawning the RoE wizard from
        inside the TUI is out of Phase 6 scope (spec §17.5: "spawning
        the wizard from the TUI is out of scope"). The notify tells the
        operator the exact command.
        """
        self.app.notify(
            "Start a new engagement with: autored run --target X --roe Y --tui",
            severity="information",
        )
