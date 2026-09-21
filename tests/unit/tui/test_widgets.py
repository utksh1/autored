import pytest
from autored.tui.widgets.phase_indicator import PhaseIndicator
from autored.tui.widgets.agent_status import AgentStatusPanel
from autored.tui.widgets.activity_log import ActivityLog


def test_phase_indicator_renders():
    widget = PhaseIndicator()
    widget.current_phase = "recon"
    # Should render without error
    assert widget.current_phase == "recon"


def test_phase_indicator_update():
    widget = PhaseIndicator()
    widget.current_phase = "recon"
    widget.update_phase("vuln")
    assert widget.current_phase == "vuln"


def test_agent_status_renders_empty():
    widget = AgentStatusPanel()
    assert widget.agent_name == ""


def test_activity_log_add_event():
    widget = ActivityLog()
    widget.add_event({
        "tool": "nmap", "target": "10.10.10.5",
        "status": "success", "duration_sec": 5.0,
    })
    # Should not crash
