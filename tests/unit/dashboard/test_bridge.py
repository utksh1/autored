# tests/unit/dashboard/test_bridge.py
"""DashboardBridge tests: drain, seq, ring buffer, scrubbing, gates."""
import asyncio
import json
from pathlib import Path

import pytest

from autored.dashboard.bridge import DashboardBridge
from autored.models.roe import RulesOfEngagement
from autored.state import EngagementState
from autored.tui.event_bus import EventBus


@pytest.fixture()
def roe() -> RulesOfEngagement:
    return RulesOfEngagement(
        engagement_name="t", operator="op", operator_signature="s",
        allowed_ips=["0.0.0.0/0"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, kernel_exploits_allowed=True,
    )


@pytest.fixture()
def state_on_disk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, roe):
    monkeypatch.chdir(tmp_path)
    state = EngagementState(
        engagement_id="eng_b", target_scope=["10.0.0.1"],
        operator="op", rules_of_engagement=roe,
    )
    state.phase = "exploit"
    eng = tmp_path / "engagements" / "eng_b"
    eng.mkdir(parents=True)
    (eng / "state.json").write_text(state.model_dump_json())
    return state


def _client_q(bridge: DashboardBridge) -> asyncio.Queue:
    q = bridge.register_client()
    return q


async def _drain_one_frame(q: asyncio.Queue) -> dict:
    return await asyncio.wait_for(q.get(), timeout=1.0)


@pytest.mark.asyncio
async def test_events_fan_out_with_seq(state_on_disk):
    bus = EventBus()
    bridge = DashboardBridge("eng_b", bus)
    q = _client_q(bridge)
    await bridge.start()
    # tool_call first so it lands at seq 1; the phase_change (seq 2) must
    # still fan out as an event frame per spec §4.
    await bus.emit_to_tui({"type": "tool_call", "node": "recon", "tool": "nmap"})
    await bus.emit_to_tui({"type": "phase_change", "node": "recon", "phase": "recon"})
    await asyncio.sleep(0.3)  # drain loop poll
    await bridge.stop()
    f1 = await _drain_one_frame(q)
    f2 = await _drain_one_frame(q)
    assert f1["type"] == "event" and f1["seq"] == 1
    assert f1["event"]["tool"] == "nmap"
    assert f2["seq"] == 2
    assert f2["event"]["type"] == "phase_change"


@pytest.mark.asyncio
async def test_hello_replays_ring_buffer(state_on_disk):
    bus = EventBus()
    bridge = DashboardBridge("eng_b", bus, max_history=2)
    await bridge.start()
    for i in range(4):
        await bus.emit_to_tui({"type": "tick", "i": i})
    await asyncio.sleep(0.3)
    await bridge.stop()
    frames = bridge.hello_frames()
    assert frames[0]["type"] == "hello"
    events = [f for f in frames if f["type"] == "event"]
    assert len(events) == 2  # max_history=2
    assert [f["event"]["i"] for f in events] == [2, 3]  # newest kept


@pytest.mark.asyncio
async def test_secret_values_scrubbed_from_event_frames(state_on_disk):
    bus = EventBus()
    bridge = DashboardBridge("eng_b", bus)
    q = _client_q(bridge)
    bridge._known_secrets = ["SuperSecret99"]
    await bridge.start()
    await bus.emit_to_tui(
        {"type": "tool_call", "output": "hash ntlm: SuperSecret99 done"}
    )
    await asyncio.sleep(0.3)
    await bridge.stop()
    frame = await _drain_one_frame(q)
    assert "SuperSecret99" not in json.dumps(frame)
    assert "[REDACTED]" in frame["event"]["output"]


@pytest.mark.asyncio
async def test_state_frames_carry_pending_gates(state_on_disk):
    bus = EventBus()
    bridge = DashboardBridge("eng_b", bus)
    q = _client_q(bridge)
    bridge._pending_gates["7"] = {
        "gate_id": "7", "gate_type": "exploit", "target": "10.0.0.1",
        "command": "msfconsole -x ...", "risks": ["r1"],
    }
    await bridge.start()
    await bus.emit_to_tui({"type": "phase_change", "node": "exploit", "phase": "exploit"})
    await asyncio.sleep(0.3)
    await bridge.stop()
    frames = []
    while not q.empty():
        frames.append(q.get_nowait())
    state_frames = [f for f in frames if f["type"] == "state"]
    assert state_frames, "phase_change must trigger a state frame"
    assert state_frames[0]["state_summary"]["pending_hitl_gates"][0]["gate_id"] == "7"


@pytest.mark.asyncio
async def test_resolve_gate_emits_orchestrator_response(state_on_disk):
    bus = EventBus()
    bridge = DashboardBridge("eng_b", bus)
    bridge._pending_gates["9"] = {
        "gate_id": "9", "gate_type": "exploit", "target": "10.0.0.1",
        "command": "cmd", "risks": [],
    }
    await bridge.resolve_gate("9", approved=True, note=None)
    response = await asyncio.wait_for(bus.wait_for_tui_response(), timeout=1.0)
    assert response == {"response": "approve"}
    await bridge.start()
    await asyncio.sleep(0.05)
    await bridge.stop()
    with pytest.raises(ValueError):
        await bridge.resolve_gate("9", approved=False, note="double")


@pytest.mark.asyncio
async def test_resolve_unknown_gate_raises(state_on_disk):
    bridge = DashboardBridge("eng_b", EventBus())
    with pytest.raises(KeyError):
        await bridge.resolve_gate("ghost", approved=True, note=None)
