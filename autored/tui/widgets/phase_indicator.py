"""PhaseIndicator widget — horizontal kill-chain phase indicator.

Spec reference: §17.4 (PhaseIndicator Widget).
"""

from __future__ import annotations

from textual.reactive import reactive
from textual.widgets import Static

PHASES = ["recon", "vuln", "exploit", "postex", "lateral", "cleanup", "report", "done"]
PHASE_EMOJI = {
    "recon": "🔍",
    "vuln": "🎯",
    "exploit": "💥",
    "postex": "🏴",
    "lateral": "➡️",
    "cleanup": "🧹",
    "report": "📝",
    "done": "✓",
}


class PhaseIndicator(Static):
    """Horizontal bar showing current phase in the kill chain."""

    current_phase = reactive("recon")

    def render(self) -> str:
        idx = PHASES.index(self.current_phase) if self.current_phase in PHASES else 0
        parts = []
        for i, phase in enumerate(PHASES):
            emoji = PHASE_EMOJI[phase]
            if i < idx:
                parts.append(f"[dim]{emoji} {phase}[/]")
            elif i == idx:
                parts.append(f"[bold reverse]{emoji} {phase}[/]")
            else:
                parts.append(f"[dim]{emoji} {phase}[/]")
        return " → ".join(parts)

    def update_phase(self, phase: str) -> None:
        self.current_phase = phase
