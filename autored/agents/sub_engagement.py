"""Sub-engagement spawner — recursive graph launcher (spec §7.2, Phase 5).

A sub-engagement is a full Phase 4 run (recon → vuln → exploit →
postex → report) rooted on a pivot target, with:

* its **own engagement ID** (``<parent>_sub_NN``) and folder under
  ``engagements/`` (manifest, raw/, evidence/, state.json),
* its **own checkpoint DB** (``engagements/<sub_id>/state.db``) so a
  crashed sub-engagement never corrupts the parent's checkpoints,
* ``parent_engagement_id`` linked on its state,
* the parent's RoE **narrowed to ``[target_host]``** — a sub-engagement
  can never touch anything outside its pivot target,
* the parent's EventBus inherited (sandbox auto-approve / TUI HitL
  responses flow through).

**Recursion is structurally capped at depth 1**: the sub-engagement
runs ``build_phase4_graph`` — the Phase 4 graph has no lateral node,
so a sub-engagement cannot spawn sub-sub-engagements. The
:class:`SubEngagementDepthError` guard below is belt-and-braces for a
future Phase 6+ recursive lateral agent (Review Focus #3).

Per the Phase 3 fix wave (I1), the EventBus travels via
``RunnableConfig["configurable"]["event_bus"]`` rather than as a
non-Pydantic state attribute — LangGraph's reducer round-trips state
through ``model_dump() + model_validate()`` which strips the
``__pydantic_extra__`` dict where ``state.event_bus = ...`` was stored.
The spawner reads the parent's bus from ``parent_state.event_bus``
(defensive — older callers may still attach it there) and propagates
it via the sub-engagement's ``RunnableConfig`` instead.

Importantly, the spawner accesses ``make_checkpointer`` via its
**source module** (``sqlite_saver.make_checkpointer``) rather than a
top-level name binding, so integration tests can patch
``autored.persistence.sqlite_saver.make_checkpointer`` and have the
patch intercepted at call time. The same dual-import pattern applies
to ``build_phase4_graph`` — the lazy import inside this function body
fetches the patched binding at call time, so tests must patch
``autored.graph.build_phase4_graph`` (NOT
``autored.agents.sub_engagement.build_phase4_graph`` — there is no such
module-level binding for the patch to mutate).
"""
from __future__ import annotations

from autored.logging import get_logger
from autored.persistence import filesystem
from autored.persistence import sqlite_saver
from autored.roe_guard import register_roe
from autored.state import EngagementState

log = get_logger("agents.sub_engagement")


class SubEngagementDepthError(Exception):
    """Raised when a sub-engagement tries to spawn its own sub-engagement."""


async def spawn_sub_engagement(
    parent_state: EngagementState,
    sub_id: str,
    target_host: str,
    pivot_method: str,
    credentials: list[str],
) -> EngagementState:
    """Spawn and run a sub-engagement against a pivot target.

    Args:
        parent_state: The parent engagement's state.
        sub_id: Sub-engagement ID (e.g. ``<parent>_sub_01``).
        target_host: The pivot target IP.
        pivot_method: Method used to pivot (for logging).
        credentials: Credential IDs used by the pivot (for logging).

    Returns:
        The sub-engagement's final hydrated ``EngagementState``.

    Raises:
        SubEngagementDepthError: if ``parent_state.parent_engagement_id``
            is set — the parent is itself a sub-engagement, so spawning
            off it would create a sub-sub-engagement and break the
            depth-1 recursion cap (Review Focus #3).
    """
    if parent_state.parent_engagement_id is not None:
        raise SubEngagementDepthError(
            f"refusing to spawn {sub_id}: {parent_state.engagement_id} "
            f"is itself a sub-engagement (max depth 1)"
        )

    log.info(
        "sub_engagement_start",
        sub_id=sub_id,
        target=target_host,
        pivot_method=pivot_method,
        creds=len(credentials),
    )

    # Own folder under engagements/<sub_id>/ (manifest, raw/, evidence/).
    filesystem.init_engagement_folder(
        sub_id, target_host, parent_state.operator
    )

    # Parent RoE narrowed to the pivot target only. A sub-engagement
    # can never touch anything outside its pivot target — even if the
    # parent RoE allowed the whole 0.0.0.0/0, the sub's allowed_ips is
    # just [target_host] (spec §7.2).
    sub_roe = parent_state.rules_of_engagement.model_copy(deep=True)
    sub_roe.allowed_ips = [target_host]

    sub_state = EngagementState(
        engagement_id=sub_id,
        parent_engagement_id=parent_state.engagement_id,
        target_scope=[target_host],
        operator=parent_state.operator,
        rules_of_engagement=sub_roe,
    )

    # Inherit the parent's EventBus so HitL auto-approve / TUI responses
    # keep flowing inside the sub-engagement. Per Phase 3 fix wave I1,
    # the bus travels via RunnableConfig, NOT as a state attribute.
    # ``getattr(parent_state, "event_bus", None)`` defensively picks
    # up the bus from callers that still attach it to state; the bus
    # is then propagated via the sub-state's config below.
    parent_bus = getattr(parent_state, "event_bus", None)

    # Register the sub-engagement's (narrowed) RoE for its tool calls.
    register_roe(sub_id, sub_roe)

    # Import here to avoid a circular import (graph.py imports agents).
    # The lazy import fetches the current binding at call time, so
    # integration tests patch ``autored.graph.build_phase4_graph`` and
    # have the patch intercepted here.
    from autored.graph import build_phase4_graph

    # ``make_checkpointer`` is accessed via the source module
    # (``sqlite_saver.make_checkpointer``) so tests can patch at
    # ``autored.persistence.sqlite_saver.make_checkpointer`` and have
    # the patch intercepted here. A top-level ``from ... import
    # make_checkpointer`` would freeze the binding at module load.
    checkpointer = await sqlite_saver.make_checkpointer(sub_id)
    graph = build_phase4_graph(checkpointer)
    config = {"configurable": {"thread_id": sub_id, "event_bus": parent_bus}}
    try:
        final = await graph.ainvoke(sub_state, config=config)
    finally:
        # Close the checkpointer connection so a crashed sub-engagement
        # never leaves a dangling SQLite handle. ``conn`` is the
        # aiosqlite connection the saver holds; ``AsyncSqliteSaver``
        # exposes it as ``.conn``.
        conn = getattr(checkpointer, "conn", None)
        if conn is not None:
            await conn.close()

    # LangGraph hands back either a dict (reducer-round-tripped) or
    # the original EngagementState (no reducer). Hydrate as a model in
    # either case so the caller sees a uniform return type.
    if isinstance(final, dict):
        final_state = EngagementState.model_validate(final)
    else:
        final_state = final

    # Persist the final state under engagements/<sub_id>/state.json.
    filesystem.save_state_to_disk(sub_id, final_state)
    log.info(
        "sub_engagement_done",
        sub_id=sub_id,
        phase=final_state.phase,
        hosts=len(final_state.hosts),
    )
    return final_state
