import pytest
import asyncio
from autored.tui.event_bus import EventBus

@pytest.mark.asyncio
async def test_event_bus_emit_and_receive():
    bus = EventBus()
    await bus.emit_to_tui({"type": "phase_change", "new_phase": "vuln"})
    event = await bus.orchestrator_to_tui.get()
    assert event["type"] == "phase_change"
    assert event["new_phase"] == "vuln"

@pytest.mark.asyncio
async def test_event_bus_tui_to_orchestrator():
    bus = EventBus()
    await bus.emit_to_orchestrator({"response": "approve"})
    response = await bus.wait_for_tui_response()
    assert response["response"] == "approve"

@pytest.mark.asyncio
async def test_try_get_tui_event_empty():
    bus = EventBus()
    event = bus.try_get_tui_event()
    assert event is None

@pytest.mark.asyncio
async def test_try_get_tui_event_returns_event():
    bus = EventBus()
    await bus.emit_to_tui({"type": "tool_call", "tool": "nmap"})
    event = bus.try_get_tui_event()
    assert event is not None
    assert event["tool"] == "nmap"
    # Second call should return None (queue empty)
    assert bus.try_get_tui_event() is None
