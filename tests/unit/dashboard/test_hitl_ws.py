# tests/unit/dashboard/test_hitl_ws.py
"""WS endpoint + HitL POST: full resolve loop against a real EventBus."""
import asyncio

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from autored.dashboard import create_app
from autored.dashboard.bridge import DashboardBridge
from autored.tui.event_bus import EventBus


@pytest.fixture()
def bridges():
    bus = EventBus()
    bridge = DashboardBridge("eng_ws", bus)
    return {"eng_ws": bridge}, bridge, bus


def test_ws_hello_frame_on_connect(bridges):
    """Smoke: a connected client receives the hello frame (drain-loop
    frame assertions live in test_bridge.py where the loop is controlled)."""
    registry, bridge, bus = bridges
    app = create_app(bridges=registry)
    with TestClient(app) as client:
        with client.websocket_connect("/ws/eng_ws") as ws:
            hello = ws.receive_json()
            assert hello["type"] == "hello"
            assert hello["engagement_id"] == "eng_ws"


def test_ws_unknown_engagement_closes_4404(bridges):
    registry, bridge, bus = bridges
    app = create_app(bridges=registry)
    with TestClient(app) as client:
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws/ghost"):
                pass
        assert exc_info.value.code == 4404


@pytest.mark.asyncio
async def test_hitl_post_resolves_pending_gate(bridges):
    registry, bridge, bus = bridges
    app = create_app(bridges=registry)
    bridge._pending_gates["3"] = {
        "gate_id": "3", "gate_type": "exploit", "target": "10.0.0.1",
        "command": "cmd", "risks": [],
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/api/engagements/eng_ws/hitl/3", json={"approved": True}
        )
        assert resp.status_code == 200
        assert resp.json()["decision"] == "approve"
        # the orchestrator contract: wait_for_tui_response returns the dict
        response = await asyncio.wait_for(bus.wait_for_tui_response(), timeout=1.0)
        assert response == {"response": "approve"}


@pytest.mark.asyncio
async def test_hitl_post_double_resolve_409(bridges):
    registry, bridge, bus = bridges
    app = create_app(bridges=registry)
    bridge._pending_gates["4"] = {
        "gate_id": "4", "gate_type": "exploit", "target": "t",
        "command": "c", "risks": [],
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        await client.post("/api/engagements/eng_ws/hitl/4", json={"approved": False})
        resp = await client.post("/api/engagements/eng_ws/hitl/4", json={"approved": True})
        assert resp.status_code == 409
        assert "reject" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_hitl_post_no_live_bridge_404(bridges):
    app = create_app(bridges={})
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/api/engagements/eng_ws/hitl/1", json={"approved": True})
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_hitl_post_unknown_gate_409(bridges):
    """Spec §5: unknown gate with a live bridge is 409, not 404 — the gate
    may exist in history as already resolved."""
    registry, bridge, bus = bridges
    app = create_app(bridges=registry)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/api/engagements/eng_ws/hitl/999", json={"approved": True}
        )
        assert resp.status_code == 409
        assert "unknown gate" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_hitl_post_non_bool_approved_422(bridges):
    """Strict body validation: approved must be a real boolean (no truthy
    string coercion), and nothing is resolved."""
    registry, bridge, bus = bridges
    app = create_app(bridges=registry)
    bridge._pending_gates["5"] = {
        "gate_id": "5", "gate_type": "exploit", "target": "t",
        "command": "c", "risks": [],
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/api/engagements/eng_ws/hitl/5", json={"approved": "yes"}
        )
        assert resp.status_code == 422
        assert resp.json()["detail"] == "approved must be a boolean"
        assert "5" in bridge._pending_gates  # gate untouched
        assert bus.tui_to_orchestrator.empty()  # nothing emitted
