"""AutoRed Phase 1 LangGraph orchestrator.

Builds the Phase 1 graph: ``roe_gate_start → recon → report_phase1 → END``
with a conditional branch out of ``recon`` that routes to ``report_phase1``
only if any hosts were discovered (else END — an empty recon result
ends the run rather than feeding an empty state into the report stub).

Phase 2's ``build_phase2_graph`` mirrors this wiring but inserts the
Vuln Agent (``vuln_node``) between ``recon`` and ``report_phase1``. It
re-uses the same empty-hosts short-circuit (I2, Phase 2 final review):
empty recon → ``report_phase1`` directly (skip ``vuln``), so a Sonnet
synthesis call isn't wasted against an empty target.

Spec ref: §10 (LangGraph wiring), §6.1 (Recon Agent), §9.1 (state shape),
§2.2 (graph definition; ``report_node_phase1`` lives in
``autored/agents/report.py``, ``roe_gate_node`` lives in
``autored/roe_guard.py``).
"""

from __future__ import annotations

from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.graph import END, StateGraph

from autored.agents.cleanup import cleanup_node
from autored.agents.exploit import exploit_node
from autored.agents.lateral import lateral_node
from autored.agents.postex import postex_node
from autored.agents.recon import recon_node
from autored.agents.report import report_node, report_node_phase1
from autored.agents.vuln import vuln_node
from autored.roe_guard import roe_gate_node
from autored.state import EngagementState


def _state_hosts(state) -> list | None:
    """Get the ``hosts`` list from state, pydantic BaseModel or plain dict.

    LangGraph passes the state schema instance to conditional-edge
    functions when the schema is a pydantic ``BaseModel`` (verified at
    graph-build time, see task-22 report). We keep a defensive
    ``.get()`` fallback in case a future langgraph version hands us a
    plain dict instead. Factored out (I2, Phase 2 final review) so both
    Phase 1 and Phase 2 recon-routers share the same host-detection
    logic rather than each open-coding it.
    """
    if hasattr(state, "hosts"):
        return state.hosts
    if hasattr(state, "get"):
        return state.get("hosts")
    return None


def _route_after_recon(state: EngagementState) -> str:
    """Phase 1 conditional edge from ``recon`` → ``report_phase1`` (or END).

    Returns ``"report_phase1"`` if any hosts were discovered, else
    ``END`` — an empty recon ends the run rather than feeding an empty
    state into the report stub.
    """
    return "report_phase1" if _state_hosts(state) else END


def _route_after_recon_phase2(state: EngagementState) -> str:
    """Phase 2 conditional edge from ``recon`` → ``vuln`` (or ``report_phase1``).

    I2 (Phase 2 final review): Phase 1 short-circuits empty recon to
    END (above), but Phase 2 originally dropped that check and uncondi-
    tionally routed ``recon → vuln`` — wasting a Sonnet synthesis call
    on an empty target. This router restores the empty-hosts short-circuit:
    non-empty hosts → ``vuln`` (Sonnet synthesises hypotheses); empty
    hosts → ``report_phase1`` (skip vuln entirely, symmetric with Phase 1).
    """
    return "vuln" if _state_hosts(state) else "report_phase1"


def build_phase1_graph(checkpointer: AsyncSqliteSaver | None = None):
    """Build the Phase 1 LangGraph: ``roe_gate → recon → report_stub → END``.

    Nodes
    -----
    - ``roe_gate_start``: idempotent RoE registration
      (``autored.roe_guard.roe_gate_node``, spec §2.2).
    - ``recon``: the LLM-planned recon loop (Task 22, ``recon_node``).
    - ``report_phase1``: stub that marks ``phase=done`` (full Report
      Agent ships in Phase 6 — currently lives in
      ``autored.agents.report``).

    Edges
    -----
    - ``roe_gate_start → recon``
    - ``recon → report_phase1`` if ``state.hosts`` is non-empty
    - ``recon → END`` otherwise (empty recon ends the run)
    - ``report_phase1 → END``

    Args
    ----
    checkpointer:
        A LangGraph checkpointer (typically
        ``AsyncSqliteSaver`` from
        ``autored.persistence.sqlite_saver.make_checkpointer``). Pass
        ``None`` to run the graph without state persistence (useful for
        tests).

    Returns
    -------
    Compiled LangGraph runnable.
    """
    graph = StateGraph(EngagementState)

    graph.add_node("roe_gate_start", roe_gate_node)
    graph.add_node("recon", recon_node)
    graph.add_node("report_phase1", report_node_phase1)

    graph.set_entry_point("roe_gate_start")
    graph.add_edge("roe_gate_start", "recon")
    graph.add_conditional_edges(
        "recon",
        _route_after_recon,
        {
            "report_phase1": "report_phase1",
            END: END,
        },
    )
    graph.add_edge("report_phase1", END)

    return graph.compile(checkpointer=checkpointer)


def build_phase2_graph(checkpointer: AsyncSqliteSaver | None = None):
    """Build the Phase 2 LangGraph: ``roe_gate → recon → vuln → report_phase1 → END``.

    Phase 2 inserts the Vuln Agent between Recon and the Phase 1 report
    stub. The Vuln Agent consumes recon findings (hosts + services +
    web apps + nuclei vulnerabilities) and produces ranked
    ``AttackHypothesis`` objects that the Phase 3 Exploit Agent will
    consume. The graph otherwise mirrors Phase 1: same RoE gate entry,
    same recon→report routing, same report stub at the end.

    Nodes
    -----
    - ``roe_gate_start``: idempotent RoE registration (``roe_gate_node``).
    - ``recon``: the LLM-planned recon loop (``recon_node``).
    - ``vuln``: the Vuln Agent LangGraph node (Task 9, ``vuln_node``).
    - ``report_phase1``: stub that marks ``phase=done``
      (``report_node_phase1``).

    Edges
    -----
    - ``roe_gate_start → recon``
    - ``recon → vuln`` if ``state.hosts`` is non-empty (I2, Phase 2
      final review: empty recon no longer wastes a Sonnet synthesis
      call against an empty target)
    - ``recon → report_phase1`` otherwise (skip vuln entirely — same
      short-circuit Phase 1 uses against END, but Phase 2 routes to
      the report stub instead so the engagement still produces a report)
    - ``vuln → report_phase1`` (always routes to report_phase1 in
      Phase 2 — whether hypotheses were produced or not, the engagement
      ends at the report stub. Phase 3 will replace this constant
      conditional with a real ``vuln → exploit`` branch.)
    - ``report_phase1 → END``

    Args
    ----
    checkpointer:
        A LangGraph checkpointer (typically
        ``AsyncSqliteSaver`` from
        ``autored.persistence.sqlite_saver.make_checkpointer``). Pass
        ``None`` to run the graph without state persistence (useful for
        tests).

    Returns
    -------
    Compiled LangGraph runnable.
    """
    graph = StateGraph(EngagementState)

    graph.add_node("roe_gate_start", roe_gate_node)
    graph.add_node("recon", recon_node)
    graph.add_node("vuln", vuln_node)
    graph.add_node("report_phase1", report_node_phase1)

    graph.set_entry_point("roe_gate_start")
    graph.add_edge("roe_gate_start", "recon")
    # I2 (Phase 2 final review): empty recon short-circuits past vuln
    # directly to report_phase1, mirroring Phase 1's empty-hosts → END
    # short-circuit. Saves a Sonnet synthesis call against an empty target.
    graph.add_conditional_edges(
        "recon",
        _route_after_recon_phase2,
        {
            "vuln": "vuln",
            "report_phase1": "report_phase1",
        },
    )
    # Phase 2 always routes vuln → report_phase1 (whether hypotheses
    # were produced or not). Phase 3 will add the exploit node here:
    # replace the constant lambda with a real state-shape router
    # (e.g., "exploit" if hypotheses else "report_phase1") and add an
    # "exploit" node to the graph.
    graph.add_conditional_edges(
        "vuln",
        lambda state: "report_phase1",
        {
            "report_phase1": "report_phase1",
        },
    )
    graph.add_edge("report_phase1", END)

    return graph.compile(checkpointer=checkpointer)


def build_phase3_graph(checkpointer: AsyncSqliteSaver | None = None):
    """Build the Phase 3 LangGraph: ``roe_gate → recon → vuln → exploit → report_phase1 → END``.

    Phase 3 inserts the Exploit Agent between the Vuln Agent and the Phase
    1 report stub. The Exploit Agent consumes the ranked
    ``AttackHypothesis`` objects produced by ``vuln`` and runs each
    hypothesis through a Human-in-the-Loop gate (the operator approves /
    rejects / edits / skips each proposed command) before execution. The
    HitL gate is **not** a LangGraph ``interrupt_before`` — it is handled
    inside ``exploit_node`` via the EventBus (TUI pushes a
    ``HitLGateModal`` and the orchestrator awaits the operator's
    response). Phase 4+ will add a ``postex`` node between ``exploit``
    and ``report_phase1`` for post-expansion + lateral movement; for now
    the graph is strictly linear (no conditional edges, no
    interrupts).

    Nodes
    -----
    - ``roe_gate_start``: idempotent RoE registration (``roe_gate_node``).
    - ``recon``: the LLM-planned recon loop (``recon_node``).
    - ``vuln``: the Vuln Agent LangGraph node (``vuln_node``).
    - ``exploit``: the Exploit Agent LangGraph node (Task 9, ``exploit_node``)
      with HitL gates routed through the EventBus + TUI modal.
    - ``report_phase1``: stub that marks ``phase=done``
      (``report_node_phase1``).

    Edges
    -----
    - ``roe_gate_start → recon`` (linear)
    - ``recon → vuln`` if ``state.hosts`` is non-empty, else
      ``recon → report_phase1`` (I4 — Phase 3 fix wave: restores the
      empty-hosts short-circuit that Phase 2's ``build_phase2_graph``
      has via ``_route_after_recon_phase2``. Phase 3 originally dropped
      it; on empty recon the graph would waste a Sonnet synthesis call
      in ``vuln_node`` + the LLM-driven plan call in ``exploit_node``
      against an empty target. The shared ``_route_after_recon_phase2``
      helper handles both Phase 2 and Phase 3 identically.)
    - ``vuln → exploit`` (linear)
    - ``exploit → report_phase1`` (linear — Phase 4 will replace this
      with a conditional edge that routes to ``postex`` when a foothold
      is achieved, else ``report_phase1``)
    - ``report_phase1 → END``

    HitL handling
    -------------
    No ``interrupt_before`` is set on the ``exploit`` node. The HitL gate
    is implemented inside ``exploit_node`` via the EventBus
    (``orchestrator_to_tui`` / ``tui_to_orchestrator`` queues): the
    exploit node emits a ``hitl_gate`` event, the TUI pushes
    ``HitLGateModal``, and the node awaits the operator's response
    envelope ``{"response": "approve"|"reject"|"edit"|"skip",
    "modified_command": str | None}`` before continuing (or skipping /
    rejecting the hypothesis). This keeps the graph compile simple and
    lets the HitL logic live with the agent that owns it.

    Per I1 (Phase 3 fix wave), the EventBus travels via
    ``RunnableConfig["configurable"]["event_bus"]`` rather than a
    non-Pydantic state attribute — LangGraph's reducer strips
    ``__pydantic_extra__`` where the previous ``state.event_bus = bus``
    was stored.

    Args
    ----
    checkpointer:
        A LangGraph checkpointer (typically
        ``AsyncSqliteSaver`` from
        ``autored.persistence.sqlite_saver.make_checkpointer``). Pass
        ``None`` to run the graph without state persistence (useful for
        tests).

    Returns
    -------
    Compiled LangGraph runnable.
    """
    graph = StateGraph(EngagementState)

    graph.add_node("roe_gate_start", roe_gate_node)
    graph.add_node("recon", recon_node)
    graph.add_node("vuln", vuln_node)
    graph.add_node("exploit", exploit_node)
    graph.add_node("report_phase1", report_node_phase1)

    graph.set_entry_point("roe_gate_start")
    graph.add_edge("roe_gate_start", "recon")
    # I4 (Phase 3 fix wave): restore the empty-hosts short-circuit
    # Phase 2 originally factored out (I2 in the Phase 2 final review)
    # and Phase 3 dropped. Empty recon now skips vuln + exploit
    # (no hypotheses to synthesise against an empty target — saves a
    # Sonnet synthesis call + the exploit-plan LLM call) and routes
    # straight to report_phase1. Mirrors Phase 2's wiring 1:1 via the
    # shared ``_route_after_recon_phase2`` helper.
    graph.add_conditional_edges(
        "recon",
        _route_after_recon_phase2,
        {
            "vuln": "vuln",
            "report_phase1": "report_phase1",
        },
    )
    graph.add_edge("vuln", "exploit")
    graph.add_edge("exploit", "report_phase1")
    graph.add_edge("report_phase1", END)

    # Phase 3: no HitL interrupts at graph level (handled inside
    # exploit_node via the EventBus + TUI HitLGateModal).
    return graph.compile(checkpointer=checkpointer)


def build_phase4_graph(checkpointer: AsyncSqliteSaver | None = None):
    """Build the Phase 4 LangGraph: ``roe_gate → recon → vuln → exploit → postex → report_phase1 → END``.

    Phase 4 inserts the Post-Ex Agent (``postex_node``) between the
    Exploit Agent and the Phase 1 report stub. The Post-Ex Agent runs
    the six sub-activities per verified foothold — enumeration,
    BloodHound (Windows-only), privesc, persistence, evasion, and
    exfiltration — with RoE hard-blocks on persistence / evasion /
    exfiltration (whole sub-activity skip) and on kernel-category
    privesc candidates, plus HitL soft-gates on the others via the
    EventBus (I1 RunnableConfig pattern). The graph is otherwise
    linear and mirrors Phase 3's wiring 1:1.

    Nodes
    -----
    - ``roe_gate_start``: idempotent RoE registration (``roe_gate_node``).
    - ``recon``: the LLM-planned recon loop (``recon_node``).
    - ``vuln``: the Vuln Agent LangGraph node (``vuln_node``).
    - ``exploit``: the Exploit Agent LangGraph node (``exploit_node``)
      with HitL gates routed through the EventBus + TUI modal.
    - ``postex``: the Post-Ex Agent LangGraph node (Task 11,
      ``postex_node``) with per-candidate RoE + HitL gates routed
      through the EventBus.
    - ``report_phase1``: stub that marks ``phase=done``
      (``report_node_phase1``).

    Edges
    -----
    - ``roe_gate_start → recon`` (linear)
    - ``recon → vuln`` if ``state.hosts`` is non-empty, else
      ``recon → report_phase1`` (I4 — preserves the empty-hosts
      short-circuit from Phase 2/3 so an empty recon skips vuln +
      exploit + postex and routes straight to the report stub,
      avoiding a Sonnet synthesis call + the exploit-plan LLM call +
      the postex enumeration sub-agent calls against an empty target.
      Shared ``_route_after_recon_phase2`` helper used by Phase 2/3.)
    - ``vuln → exploit`` (linear)
    - ``exploit → postex`` (linear — always routes to postex; the
      postex node iterates ``state.footholds`` and is a no-op when
      there are none)
    - ``postex → report_phase1`` (linear)
    - ``report_phase1 → END``

    HitL handling
    -------------
    No ``interrupt_before`` is set on any node. The HitL gates for
    privesc (per-candidate, app_system/kernel categories), persistence,
    evasion, and exfiltration are implemented inside ``postex_node``
    via the EventBus (same pattern Phase 3's ``exploit_node`` uses):
    emit a ``hitl_gate`` event, the TUI pushes ``HitLGateModal``, the
    node awaits the operator's response envelope
    ``{"response": "approve"|"reject"|"edit"|"skip", "modified_command": str | None}``
    before continuing. This keeps the graph compile simple and lets
    the HitL logic live with the agent that owns it.

    Per I1 (Phase 3 fix wave), the EventBus travels via
    ``RunnableConfig["configurable"]["event_bus"]`` rather than a
    non-Pydantic state attribute — LangGraph's reducer strips
    ``__pydantic_extra__`` where the previous ``state.event_bus = bus``
    was stored.

    Args
    ----
    checkpointer:
        A LangGraph checkpointer (typically
        ``AsyncSqliteSaver`` from
        ``autored.persistence.sqlite_saver.make_checkpointer``). Pass
        ``None`` to run the graph without state persistence (useful for
        tests).

    Returns
    -------
    Compiled LangGraph runnable.
    """
    graph = StateGraph(EngagementState)

    graph.add_node("roe_gate_start", roe_gate_node)
    graph.add_node("recon", recon_node)
    graph.add_node("vuln", vuln_node)
    graph.add_node("exploit", exploit_node)
    graph.add_node("postex", postex_node)
    graph.add_node("report_phase1", report_node_phase1)

    graph.set_entry_point("roe_gate_start")
    graph.add_edge("roe_gate_start", "recon")
    # I4 (Phase 3 fix wave, carried into Phase 4): preserve the
    # empty-hosts short-circuit Phase 2/3 use. Empty recon skips
    # vuln + exploit + postex (no hypotheses to synthesise and no
    # footholds to post-ex against an empty target — saves a Sonnet
    # synthesis call + the exploit-plan LLM call + the postex
    # enumeration sub-agent calls) and routes straight to report_phase1.
    # Shared ``_route_after_recon_phase2`` helper used by Phase 2/3/4.
    graph.add_conditional_edges(
        "recon",
        _route_after_recon_phase2,
        {
            "vuln": "vuln",
            "report_phase1": "report_phase1",
        },
    )
    graph.add_edge("vuln", "exploit")
    graph.add_edge("exploit", "postex")
    graph.add_edge("postex", "report_phase1")
    graph.add_edge("report_phase1", END)

    # Phase 4: no HitL interrupts at graph level (handled inside
    # exploit_node + postex_node via the EventBus + TUI HitLGateModal).
    return graph.compile(checkpointer=checkpointer)


def build_phase5_graph(checkpointer: AsyncSqliteSaver | None = None):
    """Build the Phase 5 LangGraph:

    ``roe_gate → recon → vuln → exploit → postex → lateral → cleanup → report_phase1 → END``.

    Phase 5 inserts the Lateral Agent (``lateral_node``) and the Cleanup
    Agent (``cleanup_node``) between the Post-Ex Agent and the Phase 1
    report stub. The Lateral Agent consumes harvested secrets + trust
    relationships to generate ranked pivot candidates, runs each through
    a RoE scope check + HitL soft-gate (EventBus), and on approval
    spawns a sub-engagement (depth-capped, scope-narrowed) per pivot.
    The Cleanup Agent then runs per-host cleanup plans — artifact
    removal + tunnel teardown + temp-file unlink + verification re-scan
    — with one final HitL confirmation gate before any removal fires.
    Both nodes are no-ops on empty state (no footholds / no artifacts),
    so the graph stays strictly linear after the recon conditional.

    Nodes
    -----
    - ``roe_gate_start``: idempotent RoE registration (``roe_gate_node``).
    - ``recon``: the LLM-planned recon loop (``recon_node``).
    - ``vuln``: the Vuln Agent LangGraph node (``vuln_node``).
    - ``exploit``: the Exploit Agent LangGraph node (``exploit_node``)
      with HitL gates routed through the EventBus + TUI modal.
    - ``postex``: the Post-Ex Agent LangGraph node (``postex_node``)
      with per-candidate RoE + HitL gates routed through the EventBus.
    - ``lateral``: the Lateral Agent LangGraph node (Task 11,
      ``lateral_node``) with per-candidate RoE scope + HitL gates +
      sub-engagement spawning, routed through the EventBus.
    - ``cleanup``: the Cleanup Agent LangGraph node (Task 12,
      ``cleanup_node``) with one plan-level HitL confirmation gate +
      per-host artifact removal + verification re-scan.
    - ``report_phase1``: stub that marks ``phase=done``
      (``report_node_phase1``).

    Edges
    -----
    - ``roe_gate_start → recon`` (linear)
    - ``recon → vuln`` if ``state.hosts`` is non-empty, else
      ``recon → report_phase1`` (I4 — preserves the empty-hosts
      short-circuit from Phase 2/3/4 so an empty recon skips vuln +
      exploit + postex + lateral + cleanup and routes straight to the
      report stub, avoiding a Sonnet synthesis call + the exploit-plan
      LLM call + the postex enumeration sub-agent calls + the lateral
      pivot sub-engagement + the cleanup removal plan against an empty
      target. Shared ``_route_after_recon_phase2`` helper used by
      Phase 2/3/4/5.)
    - ``vuln → exploit`` (linear)
    - ``exploit → postex`` (linear — always routes to postex; the
      postex node iterates ``state.footholds`` and is a no-op when
      there are none)
    - ``postex → lateral`` (linear — always routes to lateral; the
      lateral node generates pivot candidates from
      ``state.harvested_secrets`` × ``state.trust_relationships`` and
      is a no-op when either list is empty or no candidate survives
      the scope check + HitL gate)
    - ``lateral → cleanup`` (linear — always routes to cleanup; the
      cleanup node builds plans from ``state.persistence_artifacts``,
      ``state.tunnels``, ``state.evidence_paths``, and
      ``state.harvested_secrets`` and is a no-op on empty state)
    - ``cleanup → report_phase1`` (linear)
    - ``report_phase1 → END``

    HitL handling
    -------------
    No ``interrupt_before`` is set on any node. The HitL gates for
    exploit, postex, lateral, and cleanup are all implemented inside
    their respective nodes via the EventBus (same pattern Phase 3's
    ``exploit_node`` uses): emit a ``hitl_gate`` event, the TUI pushes
    ``HitLGateModal``, the node awaits the operator's response
    envelope
    ``{"response": "approve"|"reject"|"edit"|"skip", "modified_command": str | None}``
    before continuing. This keeps the graph compile simple and lets
    the HitL logic live with the agent that owns it.

    Per I1 (Phase 3 fix wave), the EventBus travels via
    ``RunnableConfig["configurable"]["event_bus"]`` rather than a
    non-Pydantic state attribute — LangGraph's reducer strips
    ``__pydantic_extra__`` where the previous ``state.event_bus = bus``
    was stored.

    Args
    ----
    checkpointer:
        A LangGraph checkpointer (typically
        ``AsyncSqliteSaver`` from
        ``autored.persistence.sqlite_saver.make_checkpointer``). Pass
        ``None`` to run the graph without state persistence (useful for
        tests).

    Returns
    -------
    Compiled LangGraph runnable.
    """
    graph = StateGraph(EngagementState)

    graph.add_node("roe_gate_start", roe_gate_node)
    graph.add_node("recon", recon_node)
    graph.add_node("vuln", vuln_node)
    graph.add_node("exploit", exploit_node)
    graph.add_node("postex", postex_node)
    graph.add_node("lateral", lateral_node)
    graph.add_node("cleanup", cleanup_node)
    graph.add_node("report_phase1", report_node_phase1)

    graph.set_entry_point("roe_gate_start")
    graph.add_edge("roe_gate_start", "recon")
    # I4 (Phase 3 fix wave, carried into Phase 4/5): preserve the
    # empty-hosts short-circuit Phase 2/3/4 use. Empty recon skips
    # vuln + exploit + postex + lateral + cleanup (no hypotheses to
    # synthesise, no footholds to post-ex, no secrets to pivot from,
    # no artifacts to clean — saves a Sonnet synthesis call + the
    # exploit-plan LLM call + the postex enumeration sub-agent calls +
    # the lateral pivot sub-engagement + the cleanup removal plan
    # against an empty target) and routes straight to report_phase1.
    # Shared ``_route_after_recon_phase2`` helper used by Phase 2/3/4/5.
    graph.add_conditional_edges(
        "recon",
        _route_after_recon_phase2,
        {
            "vuln": "vuln",
            "report_phase1": "report_phase1",
        },
    )
    graph.add_edge("vuln", "exploit")
    graph.add_edge("exploit", "postex")
    graph.add_edge("postex", "lateral")
    graph.add_edge("lateral", "cleanup")
    graph.add_edge("cleanup", "report_phase1")
    graph.add_edge("report_phase1", END)

    # Phase 5: no HitL interrupts at graph level (handled inside
    # exploit_node + postex_node + lateral_node + cleanup_node via the
    # EventBus + TUI HitLGateModal).
    return graph.compile(checkpointer=checkpointer)


def build_phase6_graph(checkpointer: AsyncSqliteSaver | None = None):
    """Build the full Phase 6 LangGraph — the complete spec §2.3 topology at last:

    ``roe_gate_start → recon → vuln → exploit → postex → lateral → cleanup → report → END``.

    Phase 6 replaces the ``report_phase1`` stub with the real Report
    Agent (``report_node`` from Task 9): the full kill chain now ends in
    generated deliverables (report.md + report.pdf + lessons.json) and
    cross-engagement memory persistence. The ``report_phase1`` stub is
    kept importable for backward compat — the Phase 1-5 graph builders
    still reference it, so ``autored resume`` on old engagements keeps
    building them.

    Topology stays linear — success/failure branching is handled inside
    the nodes (exploit exhaustion, lateral candidate loops, cleanup
    gate), exactly as in Phases 3-5, and HitL gates remain
    EventBus-based inside nodes rather than graph-level interrupts
    (documented spec §2.3 deviation carried since Phase 3).

    The Report Agent is full-auto (spec §2.4): no gate, no interrupt —
    every engagement gets its report, whatever the outcome.

    Args
    ----
    checkpointer:
        A LangGraph checkpointer (typically
        ``AsyncSqliteSaver`` from
        ``autored.persistence.sqlite_saver.make_checkpointer``). Pass
        ``None`` to run the graph without state persistence (useful for
        tests).

    Returns
    -------
    Compiled LangGraph runnable.
    """
    graph = StateGraph(EngagementState)

    graph.add_node("roe_gate_start", roe_gate_node)
    graph.add_node("recon", recon_node)
    graph.add_node("vuln", vuln_node)
    graph.add_node("exploit", exploit_node)
    graph.add_node("postex", postex_node)
    graph.add_node("lateral", lateral_node)
    graph.add_node("cleanup", cleanup_node)
    graph.add_node("report", report_node)

    graph.set_entry_point("roe_gate_start")
    graph.add_edge("roe_gate_start", "recon")
    # I4 (Phase 3 fix wave, carried into Phase 4/5/6): preserve the
    # empty-hosts short-circuit Phase 2/3/4/5 use. Empty recon skips
    # vuln + exploit + postex + lateral + cleanup (no hypotheses to
    # synthesise, no footholds to post-ex, no secrets to pivot from,
    # no artifacts to clean — saves a Sonnet synthesis call + the
    # exploit-plan LLM call + the postex enumeration sub-agent calls +
    # the lateral pivot sub-engagement + the cleanup removal plan
    # against an empty target) and routes straight to ``report`` (the
    # real Report Agent — every engagement gets a report, even an empty
    # recon one, per spec §2.4). The router still names the legacy
    # ``report_phase1`` node label for compatibility with the Phase
    # 1-5 conditional-edge dictionaries, but Phase 6's graph has no
    # ``report_phase1`` node — so we override the empty-hosts route to
    # ``report`` directly via a Phase 6-specific router.
    graph.add_conditional_edges(
        "recon",
        _route_after_recon_phase6,
        {
            "vuln": "vuln",
            "report": "report",
        },
    )
    graph.add_edge("vuln", "exploit")
    graph.add_edge("exploit", "postex")
    graph.add_edge("postex", "lateral")
    graph.add_edge("lateral", "cleanup")
    graph.add_edge("cleanup", "report")
    graph.add_edge("report", END)

    # Phase 6: no HitL interrupts at graph level (handled inside
    # exploit_node + postex_node + lateral_node + cleanup_node via the
    # EventBus + TUI HitLGateModal; the Report Agent is full-auto).
    return graph.compile(checkpointer=checkpointer)


def _route_after_recon_phase6(state: EngagementState) -> str:
    """Phase 6 conditional edge from ``recon`` → ``vuln`` (or ``report``).

    Phase 6 keeps the empty-hosts short-circuit (I4 — see
    ``_route_after_recon_phase2`` for the lineage), but routes the
    empty-hosts branch to the real ``report`` node (Phase 6's full
    Report Agent) instead of the retired ``report_phase1`` stub. Per
    spec §2.4 the Report Agent is full-auto: an empty engagement still
    gets a report (so the operator has a deliverable saying "no hosts
    discovered") rather than silently short-circuiting to END.
    """
    return "vuln" if _state_hosts(state) else "report"
