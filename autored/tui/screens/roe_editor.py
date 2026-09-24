"""RoEEditorScreen — view/edit RoE YAML with validation (spec §17.5).

The per-engagement RoE is immutable once an engagement starts (spec
glossary); this editor edits the *file* for the next engagement.

Phase 6 Task 17 adaptation: the screen inherits from ``Screen`` (not
``Container`` — Textual requires ``Screen`` for ``push_screen`` routing;
matches the pattern established by StateInspectorScreen /
FindingsTableScreen / AttackGraphScreen in Tasks 15–16).
"""
from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import Footer, Header, Static, TextArea

from autored.config import validate_roe_yaml

SANDBOX_TEMPLATE = """\
engagement_name: "Sandbox Engagement"
operator: operator
operator_signature: sandbox-mode
allowed_ips: ["0.0.0.0/0"]
allowed_techniques: ["*"]
persistence_allowed: true
evasion_allowed: true
exfiltration_allowed: true
data_destruction_allowed: false
kernel_exploits_allowed: true
hitl_mode: auto_approve
"""


class RoEEditorScreen(Screen):
    """View/edit a RoE YAML file with live validation.

    Spec §17.5: TextArea pre-loaded from ``roe_path`` (or the sandbox
    template when the file is missing); a ``Static`` validation-status
    line re-validated on every ``TextArea.Changed`` event;
    ``ctrl+s`` saves only when valid (notify on refusal); ``escape``
    returns without saving.
    """

    BINDINGS = [
        Binding("ctrl+s", "save", "Save", show=True),
        Binding("escape", "app.pop_screen", "Close", show=True),
    ]

    def __init__(self, roe_path: str) -> None:
        super().__init__()
        self.roe_path = Path(roe_path)
        self.validation_errors: list[str] = []

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(
            f"[bold]RoE Editor — {self.roe_path}[/]\n"
            "[dim](Changes apply to the NEXT engagement; a running "
            "engagement's RoE is immutable.)[/]",
            id="editor-title",
        )
        yield TextArea(self._load_text(), id="roe-text", language="yaml")
        yield Static("", id="validation-status")
        yield Footer()

    def _load_text(self) -> str:
        if self.roe_path.exists():
            return self.roe_path.read_text()
        return SANDBOX_TEMPLATE

    def on_mount(self) -> None:
        self.title = "AutoRed — RoE Editor"
        self._revalidate()

    def on_text_area_changed(self, event: TextArea.Changed) -> None:
        # Live validation — every keystroke re-validates and rewrites
        # the status line so the operator sees errors the moment they
        # introduce them (and the green VALID line the moment they
        # fix the last one).
        self._revalidate()

    def _revalidate(self) -> None:
        text_area = self.query_one(TextArea)
        self.validation_errors = validate_roe_yaml(text_area.text)
        status = self.query_one("#validation-status", Static)
        if self.validation_errors:
            status.update(
                "[bold red]INVALID[/]\n" + "\n".join(self.validation_errors[:8])
            )
        else:
            status.update("[bold green]VALID — ctrl+s to save[/]")

    def action_save(self) -> None:
        """``ctrl+s`` — write the editor contents to disk when valid.

        Refuses (with an explicit notify) when ``validation_errors``
        is non-empty so the operator never silently saves a broken
        RoE file. The notify is the explicit "no, I didn't save"
        signal — the status line already shows the errors, but the
        notify is the action-level confirmation that ``ctrl+s`` was
        received and rejected.
        """
        if self.validation_errors:
            self.app.notify(
                "Fix validation errors before saving", severity="error",
            )
            return
        self.roe_path.write_text(self.query_one(TextArea).text)
        self.app.notify(f"Saved {self.roe_path}")
