"""LangGraph orchestrator (Phases 1–3).

Graph topologies::

    Phase 1:
        roe_gate_start  ──>  recon  ──┐
                                       │
                              (hosts found?)
                                │       │
                               yes      no
                                │       │
                                v       v
                        report_phase1   END
                                │
                                v
                               END

    Phase 2:
        roe_gate_start  ──>  recon  ──>  vuln  ──>  report_phase1  ──>  END

    Phase 3:
        roe_gate_start ──> recon ──> vuln ──> exploit ──> report_phase1 ──> END

Nodes
-----
* ``roe_gate_start`` — auto-registers the engagement's RoE with the
  ``roe_guard`` registry if not already registered, then yields an empty
  state patch. This guarantees every subsequent sub-agent tool call can
  find the RoE for scope enforcement.
* ``recon`` — the Recon Agent (see :mod:`autored.agents.recon`).
* ``vuln`` — the Vuln Agent (see :mod:`autored.agents.vuln`). Phase 2+.
* ``exploit`` — the Exploit Agent (see :mod:`autored.agents.exploit`).
  Phase 3+. Iterates the Vuln Agent's ranked attack hypotheses, emits a
  HitL gate event per hypothesis (auto-approved in sandbox mode),
  dispatches the approved exploit via one of 4 specialist sub-agents,
  verifies the foothold, and captures evidence. Always transitions to
  ``report_phase1`` — Phase 4 will add the post-ex branch.
* ``report_phase1`` — stub. Phase 1 only needs to know the recon loop is
  done; the full Report Agent ships in Phase 6.

The Phase 1 ``recon`` node has a conditional edge: if at least one host
was discovered we go on to ``report_phase1``, otherwise we short-circuit
straight to ``END`` (nothing to report on). Phase 2 and Phase 3 use
linear edges — the Vuln Agent always advances to the next phase (vuln →
report in Phase 2, vuln → exploit in Phase 3), and the Exploit Agent
always advances to ``report_phase1`` (success or failure handled
internally via the EventBus + foothold-verification logic).
"""

from langgraph.graph import END, StateGraph
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

from autored.agents.recon import recon_node
from autored.agents.vuln import vuln_node
from autored.agents.exploit import exploit_node
from autored.state import EngagementState


async def roe_gate_node(state: EngagementState) -> dict:
    """Initial node: verify RoE is registered, log start.

    Returns ``None`` (rather than ``{}``) to signal "no state updates" —
    LangGraph's ``StateGraph`` raises ``InvalidUpdateError`` when a node
    returns an empty dict because the per-channel writer's
    ``all(k not in output_keys for k in input)`` check is vacuously true
    for an empty dict. Returning ``None`` is the documented way to say
    "this node updates no channels" (``StateGraph._get_state_key``
    short-circuits to ``SKIP_WRITE`` on ``None`` input).
    """
    from autored.roe_guard import _get_roe_for_engagement, register_roe

    roe = _get_roe_for_engagement(state.engagement_id)
    if roe is None:
        # Auto-register from state
        register_roe(state.engagement_id, state.rules_of_engagement)
    return None


async def report_node_phase1(state: EngagementState) -> dict:
    """Phase 1 stub: just mark phase done. Full Report Agent ships in Phase 6."""
    return {"phase": "done"}


def build_phase1_graph(checkpointer: AsyncSqliteSaver):
    """Build the Phase 1 LangGraph: roe_gate → recon → report_stub → END.

    Args:
        checkpointer: a LangGraph checkpointer (typically an
            ``AsyncSqliteSaver``) enabling resume-after-crash semantics.

    Returns:
        A compiled ``StateGraph`` ready to ``.ainvoke(...)``.
    """
    graph = StateGraph(EngagementState)

    graph.add_node("roe_gate_start", roe_gate_node)
    graph.add_node("recon", recon_node)
    graph.add_node("report_phase1", report_node_phase1)

    graph.set_entry_point("roe_gate_start")
    graph.add_edge("roe_gate_start", "recon")
    graph.add_conditional_edges(
        "recon",
        # ``state`` here is hydrated into an ``EngagementState`` Pydantic
        # model by the StateGraph's input coercion — so we use attribute
        # access (``state.hosts``) rather than dict-style ``.get()``.
        lambda state: "report_phase1" if getattr(state, "hosts", None) else END,
        {
            "report_phase1": "report_phase1",
            END: END,
        },
    )
    graph.add_edge("report_phase1", END)

    return graph.compile(checkpointer=checkpointer)


def build_phase2_graph(checkpointer: AsyncSqliteSaver):
    """Build the Phase 2 LangGraph: roe_gate → recon → vuln → report_stub → END.

    Phase 2 inserts the Vuln Agent between Recon and Report. The Vuln Agent
    consumes recon findings (services + ports + web paths) and produces
    ranked attack hypotheses ready for Phase 3's Exploit Agent.

    Topology::

        roe_gate_start  ──>  recon  ──>  vuln  ──>  report_phase1  ──>  END

    The conditional edge after ``vuln`` always routes to ``report_phase1``
    in Phase 2 — Phase 3 will replace it with a branch that runs the
    Exploit Agent when hypotheses are produced and short-circuits to
    ``report_phase1`` only when there is no viable path.

    Args:
        checkpointer: a LangGraph checkpointer (typically an
            ``AsyncSqliteSaver``) enabling resume-after-crash semantics.

    Returns:
        A compiled ``StateGraph`` ready to ``.ainvoke(...)``.
    """
    graph = StateGraph(EngagementState)

    graph.add_node("roe_gate_start", roe_gate_node)
    graph.add_node("recon", recon_node)
    graph.add_node("vuln", vuln_node)
    graph.add_node("report_phase1", report_node_phase1)

    graph.set_entry_point("roe_gate_start")
    graph.add_edge("roe_gate_start", "recon")
    graph.add_edge("recon", "vuln")
    graph.add_conditional_edges(
        "vuln",
        # Phase 2: always go to report_phase1. Phase 3 will add an exploit
        # branch here (e.g., hypotheses present → exploit, else → report).
        lambda state: "report_phase1",
        {
            "report_phase1": "report_phase1",
        },
    )
    graph.add_edge("report_phase1", END)

    return graph.compile(checkpointer=checkpointer)


def build_phase3_graph(checkpointer: AsyncSqliteSaver):
    """Build the Phase 3 LangGraph: roe_gate → recon → vuln → exploit → report → END.

    Phase 3 inserts the Exploit Agent between Vuln and Report. The Exploit
    Agent consumes the Vuln Agent's ranked attack hypotheses, presents each
    one at a HitL gate (TUI modal via EventBus — auto-approved in sandbox
    mode), dispatches the approved exploit via one of 4 specialist
    sub-agents (SQLiAgent, BruteAgent, MSFAgent, CustomAgent), verifies
    the foothold, and captures evidence. On success the agent sets
    ``phase="postex"``; on exhaustion it sets ``phase="report"``. Either
    way the linear edge to ``report_phase1`` runs the Phase 1 report stub
    (which sets ``phase="done"``).

    Topology (linear — no conditional edges)::

        roe_gate_start ──> recon ──> vuln ──> exploit ──> report_phase1 ──> END

    The ``exploit`` node handles success/failure internally (it always
    transitions to ``report_phase1`` — Phase 4 will add the post-ex branch
    that runs the Post-Ex Agent when ``phase == "postex"``).

    HitL gates are NOT modelled as LangGraph interrupts at the graph
    level — they are handled inside ``exploit_node`` via the EventBus so
    the orchestrator↔TUI communication can flow without LangGraph having
    to know about it. In sandbox mode (``hitl_mode == "auto_approve"``)
    the gates log the event and return immediately without blocking; in
    interactive mode the node blocks on ``bus.wait_for_tui_response()``
    until the operator picks approve / edit / reject / skip / abort.

    Args:
        checkpointer: a LangGraph checkpointer (typically an
            ``AsyncSqliteSaver``) enabling resume-after-crash semantics.

    Returns:
        A compiled ``StateGraph`` ready to ``.ainvoke(...)``.
    """
    graph = StateGraph(EngagementState)

    graph.add_node("roe_gate_start", roe_gate_node)
    graph.add_node("recon", recon_node)
    graph.add_node("vuln", vuln_node)
    graph.add_node("exploit", exploit_node)
    graph.add_node("report_phase1", report_node_phase1)

    graph.set_entry_point("roe_gate_start")
    graph.add_edge("roe_gate_start", "recon")
    graph.add_edge("recon", "vuln")
    graph.add_edge("vuln", "exploit")
    graph.add_edge("exploit", "report_phase1")
    graph.add_edge("report_phase1", END)

    # Phase 3: no HitL interrupts at graph level (handled inside
    # exploit_node via EventBus). The `exploit` node always transitions
    # to `report_phase1` regardless of foothold success — Phase 4 will
    # introduce the post-ex branch.
    return graph.compile(checkpointer=checkpointer)
