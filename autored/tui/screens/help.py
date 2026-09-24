"""HelpScreen — keybindings + quick reference (spec §17.4).

A simple modal-ish screen showing the AutoRed keybindings and a short
"how to drive the TUI" reference. Pushed when the operator presses ``?``.
"""
from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Markdown


HELP_MARKDOWN = """\
# AutoRed TUI — Quick Reference

## Keybindings

| Key | Action |
|-----|--------|
| `q` | Quit the app |
| `d` | Open the Dashboard |
| `?` | Open this Help screen |
| `y` | (in HitL gate) Approve |
| `n` | (in HitL gate) Reject |
| `e` | (in HitL gate) Edit command |
| `s` | (in HitL gate) Skip hypothesis |
| `Esc` | (in HitL gate) Cancel |

## Phases

`recon` → `vuln` → `exploit` → `postex` → `lateral` → `cleanup` → `report` → `done`

## HitL gates

When the Exploit Agent proposes a hypothesis, a HitL gate modal opens.
Review the technique / CVE / command, then choose:

- **y** (approve) — run the exploit as proposed
- **n** (reject) — try the next ranked hypothesis
- **e** (edit) — modify the command before running
- **s** (skip) — skip this hypothesis without rejecting the engagement

In sandbox / CI mode (`hitl_mode: auto_approve`), gates are auto-approved
without blocking.
"""


class HelpScreen(Screen):
    """Screen showing keybindings + quick reference."""

    DEFAULT_CSS = """
    HelpScreen {
        align: center middle;
    }
    HelpScreen > Markdown {
        width: 80%;
        height: 80%;
        border: round $accent;
        padding: 1 2;
        background: $surface;
    }
    """

    def compose(self) -> ComposeResult:
        # Markdown widget renders the headings + table properly. Wrap in
        # a Static-like container for the border styling (Phase 6 will
        # add scrollable container + search).
        yield Markdown(HELP_MARKDOWN, id="help-markdown")
