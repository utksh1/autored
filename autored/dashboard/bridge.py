"""EventBus → WebSocket bridge (spec §3-§4, §6, §8).

Drains ``orchestrator_to_tui`` exactly as the TUI does (alternative
frontend, never simultaneous — CLI enforces), fans JSON frames out to
registered client queues, keeps a 500-event ring buffer for late
joiners, tracks pending HitL gates, and scrubs known secret values
from event frames. Gate resolution emits the orchestrator contract
shape ``{"response": "approve"|"reject"}`` on ``tui_to_orchestrator``.
"""
from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import Any

from autored.logging import get_logger

log = get_logger("dashboard.bridge")

POLL_INTERVAL = 0.1


def _scrub(value: Any, secrets: list[str]) -> Any:
    """Replace any known secret value inside strings with [REDACTED]."""
    if isinstance(value, str) and secrets:
        for s in secrets:
            if s and s in value:
                value = value.replace(s, "[REDACTED]")
        return value
    if isinstance(value, dict):
        return {k: _scrub(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v, secrets) for v in value]
    return value


class DashboardBridge:
    """Per-engagement event tap. One bridge per live engagement."""

    def __init__(self, engagement_id: str, bus, max_history: int = 500):
        self.engagement_id = engagement_id
        self.bus = bus
        self.seq = 0
        self.max_history = max_history
        self._history: deque[dict] = deque(maxlen=max_history)
        self._clients: set[asyncio.Queue] = set()
        self._pending_gates: dict[str, dict] = {}
        self._resolved_gates: dict[str, dict] = {}
        self._known_secrets: list[str] = []
        self._last_summary: dict = {}
        self._task: asyncio.Task | None = None
        self._stopping = asyncio.Event()
        self._state_dirty = False

    # -- client plumbing ------------------------------------------------
    def register_client(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._clients.add(q)
        return q

    def unregister_client(self, q: asyncio.Queue) -> None:
        self._clients.discard(q)

    def hello_frames(self) -> list[dict]:
        return [
            {"type": "hello", "engagement_id": self.engagement_id,
             "seq": self.seq, "state_summary": self._last_summary},
            *self._history,
        ]

    def _fan_out(self, frame: dict) -> None:
        self._history.append(frame)
        for q in list(self._clients):
            q.put_nowait(frame)

    # -- lifecycle -------------------------------------------------------
    async def start(self) -> None:
        self._stopping.clear()
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._stopping.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._task = None

    async def _run(self) -> None:
        # Timers start at "now", not 0.0 — monotonic() is uptime-based, so
        # 0.0 would fire the ping/state push on the very first iteration
        # and pollute the ring buffer before any events are drained.
        last_state_push = time.monotonic()
        last_ping = time.monotonic()
        while not self._stopping.is_set():
            try:
                event = self.bus.try_get_tui_event()
                if event is not None:
                    await self._handle_event(event)
                    continue  # drain eagerly
                now = time.monotonic()
                if now - last_ping >= 15.0:
                    self._fan_out({"type": "ping", "ts": time.time()})
                    last_ping = now
                if now - last_state_push >= 5.0 or self._state_dirty:
                    # Coalesce: a dirty snapshot broadcasts only once the
                    # queue is drained, so it trails preceding events.
                    await self.broadcast_state()
                    self._state_dirty = False
                    last_state_push = now
                await asyncio.sleep(POLL_INTERVAL)
            except Exception:  # noqa: BLE001 — loop must survive bad events
                log.exception("dashboard_bridge_loop_error")
                await asyncio.sleep(POLL_INTERVAL)  # back off persistent failure

    async def _handle_event(self, event: dict) -> None:
        self.seq += 1
        if event.get("type") == "hitl_gate":
            gate_id = str(self.seq)
            gate = {
                "gate_id": gate_id,
                "gate_type": event.get("gate_type", "unknown"),
                "target": event.get("target", ""),
                "command": event.get("command", ""),
                "risks": list(event.get("risks", [])),
                "raw": event,
            }
            self._pending_gates[gate_id] = gate
            event = {**event, "gate_id": gate_id}
        scrubbed = _scrub(event, self._known_secrets)
        self._fan_out({"type": "event", "seq": self.seq, "event": scrubbed})
        if event.get("type") == "phase_change":
            # The event frame above still goes out (spec §4: every drained
            # event); the flag coalesces one state snapshot after the drain.
            self._state_dirty = True

    # -- state snapshots --------------------------------------------------
    async def broadcast_state(self) -> None:
        from autored.dashboard.api import state_summary
        from autored.persistence.filesystem import load_state_from_disk

        try:
            state = load_state_from_disk(self.engagement_id)
        except Exception as e:  # noqa: BLE001 — snapshot is best-effort
            log.warning("dashboard_state_load_failed", error=str(e))
            state = None
        if state is None:
            return
        self._known_secrets = [
            s.secret_value for s in getattr(state, "harvested_secrets", [])
            if getattr(s, "secret_value", "")
        ]
        summary = state_summary(state, ws_mode=True)
        summary["pending_hitl_gates"] = self.pending_gate_summaries()
        self._last_summary = summary
        self.seq += 1
        self._fan_out({"type": "state", "seq": self.seq, "state_summary": summary})

    def pending_gate_summaries(self) -> list[dict]:
        return _scrub(
            [
                {k: g[k] for k in ("gate_id", "gate_type", "target", "command", "risks")}
                for g in self._pending_gates.values()
            ],
            self._known_secrets,
        )

    # -- HitL resolution ---------------------------------------------------
    async def resolve_gate(self, gate_id: str, approved: bool, note: str | None) -> dict:
        if gate_id not in self._pending_gates:
            if gate_id in self._resolved_gates:
                raise ValueError(
                    f"gate {gate_id} already resolved: "
                    f"{self._resolved_gates[gate_id]['decision']}"
                )
            raise KeyError(f"unknown gate {gate_id}")
        self._resolved_gates[gate_id] = {
            "decision": "approve" if approved else "reject", "note": note,
        }
        del self._pending_gates[gate_id]
        await self.bus.emit_to_orchestrator(
            {"response": "approve" if approved else "reject"}
        )
        return {"status": "resolved",
                "decision": self._resolved_gates[gate_id]["decision"]}
