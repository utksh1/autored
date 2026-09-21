"""HelpScreen — keybindings and phase reference.

Spec reference: §17.4 (app.py references HelpScreen but does not provide
an implementation; this minimal version satisfies the SCREENS registry).
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

HELP_TEXT = """\
# AutoRed — Help

## Keybindings
  q          Quit
  d          Dashboard
  h / ?      This help screen
  y          Approve HitL gate
  n          Reject HitL gate
  e          Edit command (HitL gate)
  s          Skip HitL gate
  escape     Reject HitL gate (same as n)

## Phases
  recon    Reconnaissance (subdomain enum, port scan, web enum)
  vuln     Vulnerability analysis (CVE matching, hypothesis ranking)
  exploit  Exploit Agent (HitL gate before each attempt)
  postex   Post-exploitation (HitL gate per sub-activity)
  lateral  Lateral movement (HitL gate per pivot)
  cleanup  Cleanup Agent (removes all persistence artifacts)
  report   Report Agent (generates final engagement report)
"""


class HelpScreen(Screen):
    """Help screen — keybindings and phases."""

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(HELP_TEXT)
        yield Footer()
