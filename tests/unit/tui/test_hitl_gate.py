import pytest
from autored.tui.app import AutoRedApp
from autored.tui.screens.hitl_gate import HitLGateModal


@pytest.mark.asyncio
async def test_hitl_gate_approve():
    """Review Focus: pressing 'y' returns approve response."""
    app = AutoRedApp(engagement_id="test-001")
    async with app.run_test() as pilot:
        # Push HitL modal with test event
        event = {
            "type": "hitl_gate", "gate_type": "exploit",
            "target": "10.10.10.40", "technique": "EternalBlue",
            "cve": "CVE-2017-0144", "tool": "metasploit",
            "confidence": 0.9, "expected_outcome": "SYSTEM shell",
            "risks": ["may crash SMB"],
            "command": "msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 10.10.10.40; run'",
        }
        app.push_screen(HitLGateModal(event), lambda r: setattr(app, "_test_result", r))
        await pilot.pause()
        # Press 'y' to approve
        await pilot.press("y")
        await pilot.pause()
        assert app._test_result["response"] == "approve"


@pytest.mark.asyncio
async def test_hitl_gate_reject():
    """Review Focus: pressing 'n' returns reject response."""
    app = AutoRedApp(engagement_id="test-001")
    async with app.run_test() as pilot:
        event = {"type": "hitl_gate", "gate_type": "exploit",
                 "target": "x", "technique": "x", "cve": None,
                 "tool": "custom", "confidence": 0.5,
                 "expected_outcome": "x", "risks": [],
                 "command": "whoami"}
        app.push_screen(HitLGateModal(event), lambda r: setattr(app, "_test_result", r))
        await pilot.pause()
        await pilot.press("n")
        await pilot.pause()
        assert app._test_result["response"] == "reject"


@pytest.mark.asyncio
async def test_hitl_gate_skip():
    app = AutoRedApp(engagement_id="test-001")
    async with app.run_test() as pilot:
        event = {"type": "hitl_gate", "gate_type": "exploit",
                 "target": "x", "technique": "x", "cve": None,
                 "tool": "custom", "confidence": 0.5,
                 "expected_outcome": "x", "risks": [],
                 "command": "whoami"}
        app.push_screen(HitLGateModal(event), lambda r: setattr(app, "_test_result", r))
        await pilot.pause()
        await pilot.press("s")
        await pilot.pause()
        assert app._test_result["response"] == "skip"
