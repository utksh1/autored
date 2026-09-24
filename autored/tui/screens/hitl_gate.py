"""HitLGateModal — Human-in-the-Loop gate for the Exploit Agent (spec §17.4).

A modal screen pushed by AutoRedApp when the orchestrator emits a
``hitl_gate`` event. Displays the proposed attack hypothesis (target /
technique / CVE / confidence / expected outcome / risks / command) and
asks the operator to choose one of:

- ``y`` (approve) — run the exploit as proposed
- ``n`` (reject) — try the next ranked hypothesis
- ``e`` (edit)    — modify the command before running (placeholder — full
  edit UI lands in Phase 6 polish)
- ``s`` (skip)    — skip this hypothesis without rejecting the engagement
- ``escape``      — cancel the modal (treated as skip)

The modal dismisses with ``{"response": str, "modified_command": str | None}``.
"""
from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import ModalScreen
from textual.widgets import Static


def _format_event(event: dict[str, Any]) -> str:
    """Render the HitL event as a human-readable Rich-markup string."""
    target = event.get("target", "?")
    technique = event.get("technique", "?")
    cve = event.get("cve") or "—"
    tool = event.get("tool", "?")
    confidence = event.get("confidence", 0.0)
    expected = event.get("expected_outcome", "?")
    risks = event.get("risks", []) or []
    command = event.get("command", "")

    risks_str = ", ".join(risks) if risks else "—"
    conf_pct = int(float(confidence) * 100)
    confidence_color = (
        "red" if conf_pct >= 80 else "yellow" if conf_pct >= 50 else "cyan"
    )

    return (
        "[bold underline]Hypothesis[/bold underline]\n\n"
        f"  [bold]Target:[/bold]           {target}\n"
        f"  [bold]Technique:[/bold]        {technique}\n"
        f"  [bold]CVE:[/bold]              {cve}\n"
        f"  [bold]Tool:[/bold]             {tool}\n"
        f"  [bold]Expected:[/bold]         {expected}\n"
        f"  [bold]Confidence:[/bold]       "
        f"[{confidence_color}]{conf_pct}%[/{confidence_color}]\n"
        f"  [bold]Risks:[/bold]            {risks_str}\n\n"
        "[bold underline]Proposed command[/bold underline]\n\n"
        f"  [magenta]{command}[/magenta]\n\n"
        "[dim]────────────────────────────────────────[/dim]\n"
        "[bold]y[/bold]=approve   "
        "[bold]n[/bold]=reject   "
        "[bold]e[/bold]=edit   "
        "[bold]s[/bold]=skip   "
        "[bold]Esc[/bold]=cancel"
    )


class HitLGateModal(ModalScreen[dict]):
    """Modal screen gating the Exploit Agent on each hypothesis."""

    DEFAULT_CSS = """
    HitLGateModal {
        align: center middle;
    }
    HitLGateModal > Static {
        width: 80;
        max-height: 80%;
        border: round $warning;
        background: $surface;
        padding: 1 2;
    }
    """

    BINDINGS = [
        Binding("y", "approve", "Approve"),
        Binding("n", "reject", "Reject"),
        Binding("e", "edit", "Edit"),
        Binding("s", "skip", "Skip"),
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    def __init__(self, event: dict[str, Any], *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._event = event

    def compose(self) -> ComposeResult:
        yield Static(_format_event(self._event))

    # --- Action handlers — each dismisses with the response envelope ------

    def action_approve(self) -> None:
        """``y`` — operator approves the proposed command as-is."""
        self.dismiss({"response": "approve", "modified_command": None})

    def action_reject(self) -> None:
        """``n`` — operator rejects this hypothesis (try the next rank)."""
        self.dismiss({"response": "reject", "modified_command": None})

    def action_edit(self) -> None:
        """``e`` — operator wants to edit the command before running.

        Placeholder: dismiss with ``modified_command=None`` for now; the
        full edit-mode UI (input box + syntax highlighting + Enter to
        confirm) lands in Phase 6 TUI polish.
        """
        self.dismiss(
            {"response": "edit", "modified_command": self._event.get("command")}
        )

    def action_skip(self) -> None:
        """``s`` — skip this hypothesis without rejecting the engagement."""
        self.dismiss({"response": "skip", "modified_command": None})

    def action_cancel(self) -> None:
        """``Esc`` — cancel the modal; treated as a skip."""
        self.dismiss({"response": "skip", "modified_command": None})
