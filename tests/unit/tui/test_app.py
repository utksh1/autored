import pytest
from autored.tui.app import AutoRedApp


@pytest.mark.asyncio
async def test_app_launches():
    app = AutoRedApp(engagement_id="test-001")
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.title == "AutoRed"


@pytest.mark.asyncio
async def test_app_quit_keybinding():
    app = AutoRedApp(engagement_id="test-001")
    async with app.run_test() as pilot:
        await pilot.press("q")
        await pilot.pause()
        # App should exit
