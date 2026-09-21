import asyncio
from autored.logging import get_logger

log = get_logger("tui.event_bus")


class EventBus:
    """Bi-directional event bus between orchestrator and TUI.

    Two asyncio queues:
    - orchestrator_to_tui: events from LangGraph nodes (phase changes, tool calls, HitL gates)
    - tui_to_orchestrator: responses from operator (approve/reject/edit/skip/abort)

    Why a regular class (not ``@dataclass``)?
    ---------------------------------------
    The Phase 3 plan originally declared ``EventBus`` as a ``@dataclass``
    with two ``asyncio.Queue`` fields. That works for in-memory use, but
    LangGraph's ``AsyncSqliteSaver`` checkpointer serialises every state
    channel via ``ormsgpack`` — and ``ormsgpack`` natively serialises
    dataclasses as a dict of their fields, *before* falling back to the
    custom ``default`` hook. The ``asyncio.Queue`` instances inside the
    dataclass EventBus therefore hit ormsgpack's "Type is not msgpack
    serializable" path and crash the very first checkpoint write
    (i.e. the first time the graph tries to persist state after the
    ``recon`` node runs in any engagement that wires an EventBus onto
    its state — which is every Phase 3 engagement).

    Switching to a plain class bypasses ormsgpack's dataclass fast-path.
    LangGraph's ``JsonPlusSerializer._default`` then sees the EventBus
    instance, finds the ``model_dump`` method, and encodes it as a
    constructor call with empty kwargs — so the checkpointer writes a
    tiny placeholder, and the reviver reconstructs an empty EventBus on
    load (fine for resume: a resumed engagement gets a fresh empty
    bus, and the auto-approve sandbox path doesn't need operator input
    anyway). The in-memory EventBus instance is preserved across nodes
    during a single ``graph.ainvoke`` call, so HitL gates work
    end-to-end without round-tripping through the checkpointer.
    """

    def __init__(self) -> None:
        self.orchestrator_to_tui: asyncio.Queue = asyncio.Queue()
        self.tui_to_orchestrator: asyncio.Queue = asyncio.Queue()

    def model_dump(self) -> dict:
        """Pydantic-style dump — returns an empty placeholder dict.

        LangGraph's ``JsonPlusSerializer._default`` checks for a
        ``model_dump`` method (pydantic v2 protocol) and uses it to
        encode the object for the SQLite checkpointer. We return ``{}``
        so the serialised form is a tiny constructor call with empty
        kwargs; the queues are NOT persisted (they can't be —
        ``asyncio.Queue`` is non-serialisable and process-local).
        """
        return {}

    async def emit_to_tui(self, event: dict) -> None:
        await self.orchestrator_to_tui.put(event)

    async def emit_to_orchestrator(self, event: dict) -> None:
        await self.tui_to_orchestrator.put(event)

    async def wait_for_tui_response(self) -> dict:
        """Called by orchestrator when paused at HitL gate. Blocks until TUI responds."""
        return await self.tui_to_orchestrator.get()

    def try_get_tui_event(self) -> dict | None:
        """Non-blocking get from orchestrator_to_tui queue. Returns None if empty."""
        try:
            return self.orchestrator_to_tui.get_nowait()
        except asyncio.QueueEmpty:
            return None
