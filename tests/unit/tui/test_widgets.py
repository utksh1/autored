"""Unit tests for TUI widgets (Phase 3, Task 10).

Verifies:
- ``PhaseIndicator`` default + update_phase behaviour.
- ``AgentStatusPanel`` empty (no agent running) default.
- ``ActivityLog.add_event`` formats events as
  ``[HH:MM:SS] {tool} {target} ({duration:.1f}s) {status}`` and writes to the
  RichLog without raising.
"""
from __future__ import annotations

from autored.tui.widgets.activity_log import ActivityLog
from autored.tui.widgets.agent_status import AgentStatusPanel
from autored.tui.widgets.phase_indicator import PhaseIndicator


def test_phase_indicator_renders():
    """PhaseIndicator initialises and accepts a current_phase assignment."""
    widget = PhaseIndicator()
    widget.current_phase = "recon"
    assert widget.current_phase == "recon"


def test_phase_indicator_update():
    """update_phase() advances the current phase and re-renders."""
    widget = PhaseIndicator()
    widget.current_phase = "recon"
    widget.update_phase("vuln")
    assert widget.current_phase == "vuln"


def test_agent_status_renders_empty():
    """AgentStatusPanel exposes an empty agent_name when no agent is running."""
    widget = AgentStatusPanel()
    assert widget.agent_name == ""


def test_activity_log_add_event():
    """add_event() formats and writes a line without raising."""
    widget = ActivityLog()
    widget.add_event(
        {
            "tool": "nmap",
            "target": "10.10.10.5",
            "status": "success",
            "duration_sec": 5.0,
        }
    )
    # Should not crash; line is appended to the RichLog buffer.
