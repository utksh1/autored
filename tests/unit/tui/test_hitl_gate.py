"""Unit tests for HitLGateModal (Phase 3, Task 11).

Verifies the three required scenarios:
1. ``test_hitl_gate_approve`` — pressing 'y' dismisses with
   ``{"response": "approve", "modified_command": None}`` (Review Focus #1).
2. ``test_hitl_gate_reject`` — pressing 'n' dismisses with
   ``{"response": "reject", "modified_command": None}`` (Review Focus #1).
3. ``test_hitl_gate_skip`` — pressing 's' dismisses with
   ``{"response": "skip", "modified_command": None}``.
"""
from __future__ import annotations

import pytest

from autored.tui.app import AutoRedApp
from autored.tui.screens.hitl_gate import HitLGateModal


@pytest.mark.asyncio
async def test_hitl_gate_approve():
    """Review Focus #1: pressing 'y' returns the approve response."""
    app = AutoRedApp(engagement_id="test-001")
    async with app.run_test() as pilot:
        event = {
            "type": "hitl_gate",
            "gate_type": "exploit",
            "target": "10.10.10.40",
            "technique": "EternalBlue",
            "cve": "CVE-2017-0144",
            "tool": "metasploit",
            "confidence": 0.9,
            "expected_outcome": "SYSTEM shell",
            "risks": ["may crash SMB"],
            "command": (
                "msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; "
                "set RHOSTS 10.10.10.40; run'"
            ),
        }
        app.push_screen(
            HitLGateModal(event), lambda r: setattr(app, "_test_result", r)
        )
        await pilot.pause()
        await pilot.press("y")
        await pilot.pause()
        assert app._test_result["response"] == "approve"
        assert app._test_result["modified_command"] is None


@pytest.mark.asyncio
async def test_hitl_gate_reject():
    """Review Focus #1: pressing 'n' returns the reject response."""
    app = AutoRedApp(engagement_id="test-001")
    async with app.run_test() as pilot:
        event = {
            "type": "hitl_gate",
            "gate_type": "exploit",
            "target": "x",
            "technique": "x",
            "cve": None,
            "tool": "custom",
            "confidence": 0.5,
            "expected_outcome": "x",
            "risks": [],
            "command": "whoami",
        }
        app.push_screen(
            HitLGateModal(event), lambda r: setattr(app, "_test_result", r)
        )
        await pilot.pause()
        await pilot.press("n")
        await pilot.pause()
        assert app._test_result["response"] == "reject"
        assert app._test_result["modified_command"] is None


@pytest.mark.asyncio
async def test_hitl_gate_skip():
    """Pressing 's' returns the skip response."""
    app = AutoRedApp(engagement_id="test-001")
    async with app.run_test() as pilot:
        event = {
            "type": "hitl_gate",
            "gate_type": "exploit",
            "target": "x",
            "technique": "x",
            "cve": None,
            "tool": "custom",
            "confidence": 0.5,
            "expected_outcome": "x",
            "risks": [],
            "command": "whoami",
        }
        app.push_screen(
            HitLGateModal(event), lambda r: setattr(app, "_test_result", r)
        )
        await pilot.pause()
        await pilot.press("s")
        await pilot.pause()
        assert app._test_result["response"] == "skip"
        assert app._test_result["modified_command"] is None
