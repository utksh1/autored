"""HitLGateModal — modal that appears when an agent requests HitL approval.

Spec reference: §17.4 (HitLGateModal — the critical widget).

Phase 3 deviations from spec:
- `action_edit` dismisses with `{"response": "edit", "modified_command": None}`
  instead of pushing `EditCommandScreen` (which does not yet exist — that is
  a Phase 6 addition). The full edit flow can be wired up in Phase 6 without
  changing this file's public API.
"""

from __future__ import annotations

from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, RichLog, Static


class HitLGateModal(ModalScreen[dict]):
    """Modal that appears when an agent requests HitL approval."""

    CSS = """
    HitLGateModal {
        align: center middle;
    }
    #gate-container {
        width: 90;
        height: 30;
        border: solid $warning;
        background: $surface;
        padding: 1 2;
    }
    #gate-title {
        text-align: center;
        background: $warning;
        color: $text;
        padding: 0 1;
    }
    #gate-command {
        height: 10;
        border: solid $accent;
        margin: 1 0;
        padding: 0 1;
    }
    #gate-buttons {
        height: 3;
        align: center middle;
    }
    .gate-btn {
        margin: 0 1;
        width: 16;
    }
    #gate-btn-yes {
        background: $success;
    }
    #gate-btn-no {
        background: $error;
    }
    """

    BINDINGS = [
        Binding("y", "approve", "Approve", show=True),
        Binding("n", "reject", "Reject", show=True),
        Binding("e", "edit", "Edit", show=True),
        Binding("s", "skip", "Skip", show=True),
        Binding("escape", "reject", "Reject", show=False),
    ]

    def __init__(self, event: dict):
        super().__init__()
        self.event = event

    def compose(self) -> ComposeResult:
        with Vertical(id="gate-container"):
            yield Static(self._title_text(), id="gate-title")
            yield Static(self._details_text())
            with Vertical(id="gate-command"):
                yield RichLog()
            with Horizontal(id="gate-buttons"):
                yield Button(
                    "Approve [y]", id="gate-btn-yes", classes="gate-btn", variant="success"
                )
                yield Button(
                    "Reject [n]", id="gate-btn-no", classes="gate-btn", variant="error"
                )
                yield Button(
                    "Edit [e]", id="gate-btn-edit", classes="gate-btn", variant="warning"
                )
                yield Button("Skip [s]", id="gate-btn-skip", classes="gate-btn")

    def on_mount(self) -> None:
        # Display the proposed command with syntax highlighting.
        cmd_log = self.query_one(RichLog)
        cmd = self.event.get("command", "") or ""
        language = self._detect_language(cmd)
        cmd_log.write(Syntax(cmd, language, theme="monokai", line_numbers=True))

    def _title_text(self) -> str:
        gate_type = self.event.get("gate_type", "exploit")
        return f"  ⚠  HITL GATE — {gate_type.upper()}  ⚠  "

    def _details_text(self) -> str:
        e = self.event
        table = Table(show_header=False, box=None)
        table.add_column("Field", style="bold cyan")
        table.add_column("Value")
        table.add_row("Target", str(e.get("target", "")))
        table.add_row("Technique", str(e.get("technique", "")))
        table.add_row("CVE", str(e.get("cve", "N/A")))
        table.add_row("Tool", str(e.get("tool", "")))
        table.add_row("Confidence", f"{e.get('confidence', 0):.0%}")
        table.add_row("Expected outcome", str(e.get("expected_outcome", "")))
        risks = e.get("risks", []) or []
        table.add_row(
            "Risks",
            "\n".join(f"• {r}" for r in risks) if risks else "None listed",
        )
        return str(Panel(table, title="Proposal"))

    def _detect_language(self, cmd: str) -> str:
        if cmd.startswith("nmap") or cmd.startswith("naabu"):
            return "bash"
        if "sqlmap" in cmd:
            return "bash"
        if "python" in cmd or "import " in cmd:
            return "python"
        if "powershell" in cmd or "Invoke-" in cmd:
            return "powershell"
        return "bash"

    # ---- Action handlers for keybindings -------------------------------------

    def action_approve(self) -> None:
        self.dismiss({"response": "approve", "modified_command": None})

    def action_reject(self) -> None:
        self.dismiss({"response": "reject", "modified_command": None})

    def action_edit(self) -> None:
        # Phase 6 will wire up the full EditCommandScreen flow. For Phase 3,
        # dismiss with the edit response so the orchestrator can fall back
        # to the original command (or surface an "edit not yet supported"
        # message).
        self.dismiss({"response": "edit", "modified_command": None})

    def action_skip(self) -> None:
        self.dismiss({"response": "skip", "modified_command": None})

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "gate-btn-yes":
            self.action_approve()
        elif btn_id == "gate-btn-no":
            self.action_reject()
        elif btn_id == "gate-btn-edit":
            self.action_edit()
        elif btn_id == "gate-btn-skip":
            self.action_skip()
