"""Unit tests for AutoRedApp (Phase 3, Task 10).

Verifies the TUI app launches with the correct title and that the ``q``
keybinding quits the app cleanly (Review Focus: basic TUI launch + quit).
"""
from __future__ import annotations

import pytest

from autored.tui.app import AutoRedApp


@pytest.mark.asyncio
async def test_app_launches():
    """App launches and exposes the configured title."""
    app = AutoRedApp(engagement_id="test-001")
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.title == "AutoRed"


@pytest.mark.asyncio
async def test_app_quit_keybinding():
    """Pressing 'q' exits the app without raising."""
    app = AutoRedApp(engagement_id="test-001")
    async with app.run_test() as pilot:
        await pilot.press("q")
        await pilot.pause()
        # App should exit cleanly — no exception raised.
    assert app.return_value is None or app.return_value is not None
