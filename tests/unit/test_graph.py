"""Unit tests for the AutoRed LangGraph builders.

Phase 6 (Task 10) added the full ``build_phase6_graph`` builder — the
complete spec §2.3 topology at last: ``roe_gate_start → recon → vuln →
exploit → postex → lateral → cleanup → report → END``. The
``report_phase1`` stub is retired from the active graph (the Phase 1-5
builders still reference it for backward compat — old engagements that
resume on a Phase 1-5 checkpoint build the matching Phase 1-5 graph).

The Phase 6 tests assert the shape of the new graph: the right nodes
are present, the right edges connect them, and the CLI run command
references ``build_phase6_graph`` (not the now-deprecated Phase 4
builder). End-to-end execution is covered by the Phase 6 pipeline
integration test (``tests/integration/test_phase6_pipeline.py``).
"""
from __future__ import annotations

from pathlib import Path


def _node_names(graph_app) -> set:
    """Extract node names from a compiled LangGraph app."""
    return set(graph_app.get_graph().nodes.keys())


# --- Phase 6 (Task 10) ---------------------------------------------------- #


def test_phase6_graph_contains_all_nodes():
    from autored.graph import build_phase6_graph

    nodes = _node_names(build_phase6_graph(checkpointer=None))
    for expected in (
        "roe_gate_start", "recon", "vuln", "exploit", "postex",
        "lateral", "cleanup", "report",
    ):
        assert expected in nodes, f"missing node: {expected}"
    assert "report_phase1" not in nodes  # stub retired from the active graph


def test_phase6_graph_full_chain_edges():
    from autored.graph import build_phase6_graph

    g = build_phase6_graph(checkpointer=None).get_graph()
    edges = {(e.source, e.target) for e in g.edges}
    for expected in (
        ("roe_gate_start", "recon"), ("recon", "vuln"), ("vuln", "exploit"),
        ("exploit", "postex"), ("postex", "lateral"), ("lateral", "cleanup"),
        ("cleanup", "report"),
    ):
        assert expected in edges, f"missing edge: {expected}"


def test_cli_uses_phase6_graph():
    """The CLI run command must build the Phase 6 graph."""
    # Resolve via __file__ so the test doesn't depend on the runtime
    # CWD (pytest invocations from a non-repo-root shell still pass).
    cli_path = Path(__file__).resolve().parents[2] / "autored" / "cli.py"
    source = cli_path.read_text()
    assert "build_phase6_graph" in source
    assert "build_phase4_graph" not in source
