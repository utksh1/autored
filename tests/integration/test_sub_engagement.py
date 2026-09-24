"""Integration tests for the sub-engagement spawner (Phase 5 Task 10).

These tests verify ``spawn_sub_engagement`` in isolation:

* the depth-cap test exercises the ``SubEngagementDepthError`` guard that
  refuses to spawn a sub-engagement from a state that is itself a
  sub-engagement (Review Focus #3, spec §7.2 "sub-graph recursion");
* the happy-path test patches ``autored.graph.build_phase4_graph`` at the
  **source module** (the lazy ``from autored.graph import
  build_phase4_graph`` inside ``spawn_sub_engagement`` fetches the
  patched binding at call time, so patching the agent module's namespace
  would NOT intercept it — this is the dual-import pattern documented in
  ``autored/agents/postex.py``) and the ``make_checkpointer`` factory at
  its source module (the impl accesses it via ``sqlite_saver.
  make_checkpointer`` rather than a top-level name binding, so the
  patch IS intercepted).

Asserts on the happy path: own engagement folder + checkpoint DB +
persisted state.json under ``engagements/<sub_id>/``, parent link set,
scope narrowed to ``[target_host]``, final state hydrated as
``EngagementState`` with ``phase == "done"``.
"""
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from autored.agents.sub_engagement import (
    SubEngagementDepthError,
    spawn_sub_engagement,
)
from autored.models.roe import RulesOfEngagement
from autored.persistence.sqlite_saver import (
    make_checkpointer as _real_make_checkpointer,
)
from autored.state import EngagementState

FIXTURES = Path(__file__).parents[2] / "tests" / "fixtures"


def _roe() -> RulesOfEngagement:
    return RulesOfEngagement(
        engagement_name="sub",
        operator="op",
        operator_signature="s",
        allowed_ips=["0.0.0.0/0"],
        allowed_techniques=["*"],
        persistence_allowed=True,
        evasion_allowed=True,
        exfiltration_allowed=True,
        kernel_exploits_allowed=True,
        hitl_mode="auto_approve",
    )


def _parent(tmp_path, monkeypatch) -> EngagementState:
    monkeypatch.chdir(tmp_path)
    return EngagementState(
        engagement_id="parent-1",
        target_scope=["192.168.56.22"],
        operator="op",
        rules_of_engagement=_roe(),
    )


async def _mock_graph_ainvoke(state, config=None):
    """Mock ``graph.ainvoke``: echo the input state as a dict with phase='done'.

    The real Phase 4 graph would round-trip the state through the
    LangGraph reducer (``model_dump() + model_validate()``) and end at
    the report stub (``phase="done"``). For the integration test we
    short-circuit the whole chain — the mock just echoes the sub-state
    back with ``phase="done"`` so ``spawn_sub_engagement`` exercises
    every persistence + hydration step without needing ~30 LLM /
    subprocess / subagent mocks (those are covered by
    ``test_phase4_pipeline.py``).
    """
    if hasattr(state, "model_dump"):
        d = state.model_dump()
    else:
        d = dict(state)
    d["phase"] = "done"
    return d


async def test_depth_cap_raises_from_sub_state(tmp_path, monkeypatch):
    """Review Focus #3: spawning from a sub-engagement raises.

    A state whose ``parent_engagement_id`` is set is itself a
    sub-engagement; spawning off it would create a sub-sub-engagement
    and break the depth-1 cap. The guard raises
    ``SubEngagementDepthError`` with a belt-and-braces message (the
    structural cap is the Phase 4 graph having no lateral node, but the
    guard future-proofs against a recursive lateral agent in Phase 6+).
    """
    parent = _parent(tmp_path, monkeypatch)
    parent.parent_engagement_id = "grandparent-1"
    with pytest.raises(SubEngagementDepthError) as excinfo:
        await spawn_sub_engagement(
            parent_state=parent,
            sub_id="parent-1_sub_01",
            target_host="192.168.56.11",
            pivot_method="wmiexec",
            credentials=["s-1"],
        )
    msg = str(excinfo.value)
    assert "parent-1_sub_01" in msg, (
        f"depth-cap error should name the refused sub_id; got {msg!r}"
    )
    assert "parent-1" in msg, (
        f"depth-cap error should name the parent engagement_id; got {msg!r}"
    )
    assert "max depth 1" in msg, (
        f"depth-cap error should mention the depth cap; got {msg!r}"
    )


async def test_happy_path_spawns_phase4_graph(tmp_path, monkeypatch):
    """Happy path: spawn sub-engagement with Phase 4 graph mocked.

    Patches ``autored.graph.build_phase4_graph`` to return a mock graph
    whose ``ainvoke`` echoes the sub-state with ``phase="done"`` (no
    real LLM / subprocess / subagent mocks needed — those are covered
    by ``test_phase4_pipeline.py``). Patches
    ``autored.persistence.sqlite_saver.make_checkpointer`` with a
    ``side_effect`` that calls the real factory, so the state.db file
    is actually created on disk (the brief's assertion requires it).
    """
    from autored.persistence.filesystem import init_engagement_folder

    parent = _parent(tmp_path, monkeypatch)
    init_engagement_folder("parent-1", "192.168.56.22", "op")

    mock_graph = MagicMock()
    mock_graph.ainvoke = AsyncMock(side_effect=_mock_graph_ainvoke)

    with patch(
        "autored.graph.build_phase4_graph", return_value=mock_graph
    ), patch(
        "autored.persistence.sqlite_saver.make_checkpointer",
        side_effect=_real_make_checkpointer,
    ):
        final = await spawn_sub_engagement(
            parent_state=parent,
            sub_id="parent-1_sub_01",
            target_host="192.168.56.11",
            pivot_method="wmiexec",
            credentials=["s-1"],
        )

    # Own folder + checkpoint DB + persisted state under engagements/<sub_id>/
    sub_dir = tmp_path / "engagements" / "parent-1_sub_01"
    assert (sub_dir / "raw").is_dir(), (
        f"sub-engagement folder raw/ missing at {sub_dir / 'raw'}"
    )
    assert (sub_dir / "state.db").exists(), (
        f"checkpoint DB state.db missing at {sub_dir / 'state.db'}"
    )
    assert (sub_dir / "state.json").exists(), (
        f"persisted state.json missing at {sub_dir / 'state.json'}"
    )
    persisted = json.loads((sub_dir / "state.json").read_text())
    assert persisted["engagement_id"] == "parent-1_sub_01", (
        f"persisted state.engagement_id mismatch; got "
        f"{persisted.get('engagement_id')!r}"
    )

    # Returned state: hydrated EngagementState, parent linked, scope narrowed
    assert isinstance(final, EngagementState), (
        f"spawn_sub_engagement should return EngagementState; got {type(final)}"
    )
    assert final.engagement_id == "parent-1_sub_01"
    assert final.parent_engagement_id == "parent-1", (
        "sub-state must link back to parent engagement_id"
    )
    assert final.target_scope == ["192.168.56.11"], (
        "sub-state target_scope must be narrowed to [target_host]"
    )
    assert final.rules_of_engagement.allowed_ips == ["192.168.56.11"], (
        "sub-state RoE allowed_ips must be narrowed to [target_host]"
    )
    assert final.phase == "done", (
        f"final phase must be 'done' (report stub ran); got {final.phase!r}"
    )
