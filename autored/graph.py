"""Phase 1 LangGraph orchestrator.

Graph topology::

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

Nodes
-----
* ``roe_gate_start`` — auto-registers the engagement's RoE with the
  ``roe_guard`` registry if not already registered, then yields an empty
  state patch. This guarantees every subsequent sub-agent tool call can
  find the RoE for scope enforcement.
* ``recon`` — the Recon Agent (see :mod:`autored.agents.recon`).
* ``report_phase1`` — stub. Phase 1 only needs to know the recon loop is
  done; the full Report Agent ships in Phase 6.

The ``recon`` node has a conditional edge: if at least one host was
discovered we go on to ``report_phase1``, otherwise we short-circuit
straight to ``END`` (nothing to report on).
"""

from langgraph.graph import END, StateGraph
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

from autored.agents.recon import recon_node
from autored.agents.vuln import vuln_node
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
