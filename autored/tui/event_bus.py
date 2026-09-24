"""EventBus — bi-directional orchestrator ↔ TUI channel (spec §17.7).

Two asyncio queues bridge the LangGraph orchestrator and the operator-facing
TUI:
- ``orchestrator_to_tui``: LangGraph nodes emit phase changes, tool calls,
  and Human-in-the-Loop gate events. The TUI reads from this queue.
- ``tui_to_orchestrator``: The TUI emits operator responses
  (approve/reject/edit/skip/abort). The orchestrator reads from this queue,
  typically while paused at a HitL gate.

The bus is a plain ``@dataclass`` (NOT a Pydantic model) because the queues
are runtime-only, non-serialisable handles — see spec §17.7.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from autored.logging import get_logger

log = get_logger("tui.event_bus")


@dataclass
class EventBus:
    """Bi-directional event bus between orchestrator and TUI.

    Two asyncio queues:
    - orchestrator_to_tui: events from LangGraph nodes (phase changes,
      tool calls, HitL gates).
    - tui_to_orchestrator: responses from operator (approve/reject/edit/
      skip/abort).
    """

    orchestrator_to_tui: asyncio.Queue = field(default_factory=asyncio.Queue)
    tui_to_orchestrator: asyncio.Queue = field(default_factory=asyncio.Queue)

    async def emit_to_tui(self, event: dict) -> None:
        """Push an event onto the orchestrator→TUI queue."""
        await self.orchestrator_to_tui.put(event)

    async def emit_to_orchestrator(self, event: dict) -> None:
        """Push a response onto the TUI→orchestrator queue."""
        await self.tui_to_orchestrator.put(event)

    async def wait_for_tui_response(self) -> dict:
        """Called by orchestrator when paused at a HitL gate. Blocks until TUI responds."""
        return await self.tui_to_orchestrator.get()

    def try_get_tui_event(self) -> dict | None:
        """Non-blocking get from orchestrator_to_tui queue. Returns None if empty."""
        try:
            return self.orchestrator_to_tui.get_nowait()
        except asyncio.QueueEmpty:
            return None
