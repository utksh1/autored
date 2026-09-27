# autored/dashboard/ws.py
"""WebSocket fan-out endpoint (spec §4, §8).

The HitL POST lives in ``api.py`` (Task 5) where the per-app bridge
registry closure exists — this module only owns the WS endpoint.
"""
from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from autored.logging import get_logger

log = get_logger("dashboard.ws")

router = APIRouter()


@router.websocket("/ws/{engagement_id}")
async def ws_endpoint(websocket: WebSocket, engagement_id: str) -> None:
    bridges = websocket.app.state.bridges
    bridge = bridges.get(engagement_id)
    if bridge is None:
        await websocket.close(code=4404)
        return
    await websocket.accept()
    q = bridge.register_client()
    try:
        for frame in bridge.hello_frames():
            await websocket.send_json(frame)
        while True:
            client_msg = await websocket.receive_json()
            # Only pings are defined client→server (spec §4) — receive and
            # ignore; reconnect handles staleness.
            _ = client_msg
    except WebSocketDisconnect:
        pass
    finally:
        bridge.unregister_client(q)
