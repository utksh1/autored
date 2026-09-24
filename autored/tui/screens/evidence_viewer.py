"""EvidenceViewerScreen — view captured evidence (spec §17.5).

Text evidence renders with syntax highlighting; screenshots (and any
binary) render as metadata — Textual cannot draw images natively.

Phase 6 Task 14 adaptation note: the plan was authored against Textual
0.79's ``TabbedContentItem`` widget, which was renamed to ``TabPane`` in
Textual 0.86 (carried through 8.x). This screen uses ``TabPane`` so it
works against the installed Textual runtime. The screen also inherits
from ``Screen`` (not ``Container`` — Textual requires ``Screen`` for
``push_screen`` routing; a ``Container`` raises a ``ScreenError`` when
pushed).
"""
from __future__ import annotations

from pathlib import Path

from rich.syntax import Syntax
from textual.app import ComposeResult
from textual.containers import ScrollableContainer
from textual.screen import Screen
from textual.widgets import Footer, Header, Static, TabbedContent, TabPane

# Spec §17.5: shell-session transcripts, command output, scan JSON,
# markdown notes — all render as syntax-highlighted text. Screenshots
# (PNG) and any other binary surface as metadata because Textual has no
# native image rendering.
TEXT_SUFFIXES = {".txt", ".log", ".out", ".jsonl", ".json", ".md", ".err"}

# Hard cap on per-file text content so a multi-MB scan dump doesn't
# freeze the TUI on a single ``Static(Syntax(...))`` render.
MAX_TEXT_CHARS = 200_000


class EvidenceViewerScreen(Screen):
    """View captured evidence: shell sessions, command output, screenshots.

    ``engagement_id`` is the live engagement the dashboard is bound to;
    evidence files are read from ``engagements/<id>/evidence/`` (sorted
    alphabetically so the operator can ``Tab`` through them in a stable
    order).
    """

    BINDING_HINT = "Evidence viewer (v)"

    def __init__(self, engagement_id: str) -> None:
        super().__init__()
        self.engagement_id = engagement_id
        self.evidence_dir = Path("engagements") / engagement_id / "evidence"

    def compose(self) -> ComposeResult:
        yield Header()
        # ``evidence_dir.exists()`` returns False for both "no dir" and
        # "empty dir", so we glob to distinguish — an existing empty dir
        # yields an empty list (which still triggers the "no evidence"
        # message); a missing dir likewise yields an empty list.
        evidence_files = (
            sorted(self.evidence_dir.glob("*"))
            if self.evidence_dir.exists()
            else []
        )
        if not evidence_files:
            yield Static(
                f"[dim]No evidence captured for {self.engagement_id}.[/]",
                id="evidence-empty",
            )
        else:
            with TabbedContent():
                for evidence_file in evidence_files:
                    with TabPane(title=evidence_file.name):
                        yield self._render_evidence(evidence_file)
        yield Footer()

    def _render_evidence(self, path: Path) -> Static | ScrollableContainer:
        """Render one evidence file as either a syntax block or metadata.

        Text files (`.txt`/`.log`/`.out`/`.jsonl`/`.json`/`.md`/`.err`)
        are read with ``errors="ignore"`` so a UTF-8 terminal never
        crashes on a binary blob slipped into a ``.log`` file. Content is
        capped at ``MAX_TEXT_CHARS`` (200k) to bound the Syntax render.

        Any other suffix (`.png` screenshots, `.pcap` captures, etc.)
        renders as a metadata block — Textual has no native image widget,
        so the operator is told the path + size and asked to open it
        externally.
        """
        if path.suffix.lower() in TEXT_SUFFIXES:
            content = path.read_text(errors="ignore")[:MAX_TEXT_CHARS]
            return ScrollableContainer(
                Static(
                    Syntax(
                        content,
                        "bash",
                        theme="monokai",
                        line_numbers=True,
                    )
                ),
            )
        size = path.stat().st_size if path.exists() else 0
        return Static(
            f"[Screenshot]\nPath: {path}\nSize: {size} bytes\n\n"
            f"[dim](Textual cannot render {path.suffix} files inline)[/]"
        )
