"""PhaseIndicator widget — current kill-chain phase (spec §17.4).

A horizontal "you are here" indicator across the 8 AutoRed phases:
recon → vuln → exploit → postex → lateral → cleanup → report → done.
"""
from __future__ import annotations

from textual.reactive import reactive
from textual.widgets import Static


class PhaseIndicator(Static):
    """Static widget showing the current kill-chain phase.

    Re-renders on every ``current_phase`` change (Textual reactives trigger
    a refresh automatically). The strip layout / emoji polish lands in
    Phase 6 per the spec.
    """

    DEFAULT_CSS = """
    PhaseIndicator {
        height: 3;
        padding: 0 1;
        background: $surface;
        border: round $primary;
    }
    """

    PHASES: list[str] = [
        "recon",
        "vuln",
        "exploit",
        "postex",
        "lateral",
        "cleanup",
        "report",
        "done",
    ]

    PHASE_EMOJI: dict[str, str] = {
        "recon": "🔍",
        "vuln": "🛡",
        "exploit": "💥",
        "postex": "⚙",
        "lateral": "↪",
        "cleanup": "🧹",
        "report": "📋",
        "done": "✓",
    }

    current_phase: reactive[str] = reactive[str]("recon")

    def update_phase(self, new_phase: str) -> None:
        """Advance the indicator to ``new_phase`` and trigger re-render."""
        if new_phase not in self.PHASES:
            # Defensive — a malformed phase name should not crash the TUI.
            return
        self.current_phase = new_phase

    def render(self) -> str:
        """Render the full 8-phase strip with the active phase highlighted."""
        active_idx = (
            self.PHASES.index(self.current_phase)
            if self.current_phase in self.PHASES
            else 0
        )
        parts: list[str] = []
        for idx, phase in enumerate(self.PHASES):
            emoji = self.PHASE_EMOJI.get(phase, "?")
            if idx == active_idx:
                parts.append(f"[bold reverse]{emoji} {phase}[/bold reverse]")
            elif idx < active_idx:
                parts.append(f"[dim]{emoji} {phase}[/dim]")
            else:
                parts.append(f"[dim]{emoji}[/dim]")
        return "  ".join(parts)
