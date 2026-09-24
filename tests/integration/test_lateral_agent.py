"""Integration tests for the Lateral Agent node (Phase 5 Task 11).

Direct-node-entry pattern (same as ``tests/integration/test_postex_agent.py``):
construct an ``EngagementState``, patch the sub-agent @tool entrypoints at
their ``autored.agents.lateral`` aliases, call ``lateral_node`` directly
with a ``RunnableConfig``-shaped dict, and assert the returned state-dict
patch.

I1 (Phase 3 fix wave): the EventBus travels via
``config["configurable"]["event_bus"]`` (RunnableConfig), NOT via
``state.event_bus``. LangGraph's reducer round-trips state through
``model_dump() + model_validate()`` which strips the
``__pydantic_extra__`` dict where ``state.event_bus = ...`` was stored
under ``extra="allow"``. The RunnableConfig is the standard LangGraph
channel for runtime objects (it never crosses the reducer boundary).
Each test here calls ``lateral_node`` directly with the
``_config_with_bus(bus)`` helper, mirroring the production CLI call shape
(see ``autored/cli.py`` ``run``).

Sub-agent imports are MODULE-LEVEL in ``autored.agents.lateral`` so test
patches like ``patch("autored.agents.lateral.pivotexecutor_subagent")``
are visible to the helpers at call time — the helpers reference the
module globals, which ``patch`` replaces in-place.
"""
from datetime import datetime
from unittest.mock import AsyncMock, patch

import pytest

from autored.agents.lateral import (
    MAX_PIVOTS,
    _calculate_confidence,
    _extract_username_from_source,
    _identify_pivot_candidates,
    _select_pivot_method,
    lateral_node,
)
from autored.models.foothold import Foothold
from autored.models.host import Host
from autored.models.lateral import PivotRecord
from autored.models.postex import Secret, Trust
from autored.models.roe import RulesOfEngagement
from autored.state import EngagementState
from autored.tui.event_bus import EventBus


def _roe(allowed_ips=None, hitl_mode="auto_approve") -> RulesOfEngagement:
    return RulesOfEngagement(
        engagement_name="t",
        operator="op",
        operator_signature="s",
        allowed_ips=allowed_ips or ["0.0.0.0/0"],
        allowed_techniques=["*"],
        persistence_allowed=True,
        evasion_allowed=True,
        exfiltration_allowed=True,
        kernel_exploits_allowed=True,
        hitl_mode=hitl_mode,
    )


def _state(**kwargs) -> EngagementState:
    s = EngagementState(
        engagement_id="eng-1",
        target_scope=["192.168.56.22"],
        operator="op",
        rules_of_engagement=_roe(
            **{k: v for k, v in kwargs.items() if k in ("allowed_ips", "hitl_mode")}
        ),
    )
    s.hosts = [
        Host(
            ip="192.168.56.22",
            discovered_at=datetime.utcnow(),
            discovered_by="nmap",
        ),
        Host(
            ip="192.168.56.11",
            discovered_at=datetime.utcnow(),
            discovered_by="nmap",
        ),
    ]
    # Foothold on host 1 only — host 2 is the pivot target.
    s.footholds = [
        Foothold(
            id="f-1",
            host_ip="192.168.56.22",
            username="svc",
            context="user",
            method="ms17_010",
            access_type="shell",
            evidence_path="e",
            established_at=datetime.utcnow(),
            hypothesis_rank=1,
        ),
    ]
    s.harvested_secrets = [
        Secret(
            host_ip="192.168.56.22",
            secret_type="hash",
            secret_value="31d6cfe0d16ae931b73c59d7e0c089c0",
            source="secretsdump:SAM/administrator",
        ),
    ]
    return s


def _pivot_output(success=True):
    from autored.subagents.pivotexecutor import PivotExecutorOutput

    return PivotExecutorOutput(
        pivot=PivotRecord(
            target_host="192.168.56.11",
            method="wmiexec",
            credentials_used=["<sid>"],
            success=success,
            needs_tunnel=False,
        ),
        success=success,
        output="goad\\administrator",
    )


def _fake_sub_state(phase="done"):
    s = _state()
    s.engagement_id = "eng-1_sub_01"
    s.parent_engagement_id = "eng-1"
    s.phase = phase
    s.summary = "sub engagement done"
    return s


def _config_with_bus(bus) -> dict:
    """Build a RunnableConfig-shaped dict carrying the EventBus (I1 pattern).

    Mirrors what the production CLI does (``autored/cli.py`` ``run``
    command): ``config = {"configurable": {"event_bus": bus, ...}}``.
    Passing ``bus=None`` simulates a headless ``--no-tui`` run.
    """
    return {"configurable": {"event_bus": bus}}


async def test_happy_path_pivot_and_sub_engagement(tmp_path, monkeypatch):
    """Happy path: one candidate, one pivot, one sub-engagement spawn.

    Asserts the returned state-dict patch carries:
    - ``phase="cleanup"`` (advance)
    - one ``PivotRecord`` for the un-footholded host
    - one ``SubEngagementRef`` with the expected sub_id / status / path
    - one ``MovementPath`` from the foothold host to the pivot target
    - the candidate dict passed to the executor carries the parsed
      username, the selected method, and the target host.
    """
    monkeypatch.chdir(tmp_path)
    state = _state()
    config = _config_with_bus(None)
    with (
        patch("autored.agents.lateral.pivotexecutor_subagent") as mock_pivot,
        patch("autored.agents.lateral.tunnelsetup_subagent") as mock_tunnel,
        patch(
            "autored.agents.lateral.spawn_sub_engagement",
            new_callable=AsyncMock,
            return_value=_fake_sub_state(),
        ) as mock_spawn,
    ):
        mock_pivot.ainvoke = AsyncMock(return_value=_pivot_output())
        mock_tunnel.ainvoke = AsyncMock(return_value=None)
        result = await lateral_node(state, config)

    assert result["phase"] == "cleanup"
    assert len(result["pivots"]) == 1
    assert result["pivots"][0].target_host == "192.168.56.11"
    assert result["pivots"][0].success is True
    assert len(result["sub_engagements"]) == 1
    ref = result["sub_engagements"][0]
    assert ref.sub_id == "eng-1_sub_01"
    assert ref.status == "completed"
    assert ref.sub_state_path == "engagements/eng-1_sub_01/state.json"
    assert len(result["movement_paths"]) == 1
    assert result["movement_paths"][0].from_host == "192.168.56.22"
    assert result["movement_paths"][0].to_host == "192.168.56.11"
    mock_spawn.assert_awaited_once()
    # candidate was passed to the executor as a positional input dict
    # (LangChain @tool invocation pattern — same shape postex uses for
    # windowsenum / credharvester / etc).
    invoke_input = mock_pivot.ainvoke.call_args.args[0]
    assert invoke_input["candidate"]["username"] == "administrator"
    assert invoke_input["candidate"]["method"] == "wmiexec"
    assert invoke_input["candidate"]["target_host"] == "192.168.56.11"
    assert invoke_input["engagement_id"] == "eng-1"


async def test_out_of_scope_target_skipped_before_hitl(tmp_path, monkeypatch):
    """Review Focus #1: RoE allowed_ips excludes the pivot target →
    candidate skipped entirely; executor never called.

    The scope pre-check runs BEFORE the HitL gate — an operator is
    never asked to approve something the scope forbids (mirrors Phase 4's
    kernel-exploit RoE short-circuit). The pivotexecutor_subagent is
    never awaited; spawn_sub_engagement is never awaited either.
    """
    monkeypatch.chdir(tmp_path)
    state = _state(allowed_ips=["192.168.56.22/32"])
    config = _config_with_bus(None)
    with (
        patch("autored.agents.lateral.pivotexecutor_subagent") as mock_pivot,
        patch(
            "autored.agents.lateral.spawn_sub_engagement",
            new_callable=AsyncMock,
            return_value=_fake_sub_state(),
        ) as mock_spawn,
    ):
        mock_pivot.ainvoke = AsyncMock(return_value=_pivot_output())
        result = await lateral_node(state, config)
    assert result["pivots"] == []
    mock_pivot.ainvoke.assert_not_awaited()
    mock_spawn.assert_not_awaited()
    assert result["phase"] == "cleanup"


async def test_failed_pivot_tries_next_candidate(tmp_path, monkeypatch):
    """Review Focus #2: first candidate fails → agent continues to the
    next candidate (second secret on the same target).

    The first pivot executor call returns ``success=False``; the loop
    logs the failure and moves on. The second call returns a successful
    pivot, which is recorded (and a sub-engagement spawned).
    """
    monkeypatch.chdir(tmp_path)
    state = _state()
    state.harvested_secrets.append(
        Secret(
            host_ip="192.168.56.22",
            secret_type="password",
            secret_value="Password1!",
            source="credharvester:manual/bob",
        ),
    )
    config = _config_with_bus(None)
    with (
        patch("autored.agents.lateral.pivotexecutor_subagent") as mock_pivot,
        patch(
            "autored.agents.lateral.spawn_sub_engagement",
            new_callable=AsyncMock,
            return_value=_fake_sub_state(),
        ) as mock_spawn,
    ):
        mock_pivot.ainvoke = AsyncMock(
            side_effect=[_pivot_output(success=False), _pivot_output()],
        )
        result = await lateral_node(state, config)
    assert mock_pivot.ainvoke.await_count == 2
    assert len(result["pivots"]) == 1  # only the successful one recorded
    assert result["pivots"][0].success is True
    mock_spawn.assert_awaited_once()


async def test_depth_cap_error_skips_sub_engagement(tmp_path, monkeypatch):
    """Review Focus #3: SubEngagementDepthError → logged, sub skipped,
    the pivot itself is still recorded.

    The parent state's ``parent_engagement_id`` is set, so
    ``spawn_sub_engagement`` raises ``SubEngagementDepthError``. The
    lateral_node catches it, logs a warning, and continues without
    appending a SubEngagementRef — but the pivot itself is still
    recorded (the pivot succeeded; only the recursive sub-engagement
    is skipped).
    """
    monkeypatch.chdir(tmp_path)
    state = _state()
    state.parent_engagement_id = "grandparent"
    config = _config_with_bus(None)
    from autored.agents.sub_engagement import SubEngagementDepthError

    with (
        patch("autored.agents.lateral.pivotexecutor_subagent") as mock_pivot,
        patch(
            "autored.agents.lateral.spawn_sub_engagement",
            new_callable=AsyncMock,
            side_effect=SubEngagementDepthError("depth"),
        ) as mock_spawn,
    ):
        mock_pivot.ainvoke = AsyncMock(return_value=_pivot_output())
        result = await lateral_node(state, config)
    assert len(result["pivots"]) == 1
    assert result["sub_engagements"] == []
    mock_spawn.assert_awaited_once()


async def test_hitl_rejection_skips_candidate(tmp_path, monkeypatch):
    """Operator rejects the pivot via the HitL gate → candidate skipped.

    The bus is pre-loaded with a ``{"approved": False}`` response so
    ``bus.wait_for_tui_response()`` returns it immediately. The gate
    returns ``False``; the loop skips the candidate (the pivotexecutor
    is never awaited).
    """
    monkeypatch.chdir(tmp_path)
    state = _state(hitl_mode="always_ask")
    bus = EventBus()
    await bus.emit_to_orchestrator({"type": "hitl_response", "approved": False})
    config = _config_with_bus(bus)
    with (
        patch("autored.agents.lateral.pivotexecutor_subagent") as mock_pivot,
        patch(
            "autored.agents.lateral.spawn_sub_engagement",
            new_callable=AsyncMock,
            return_value=_fake_sub_state(),
        ) as mock_spawn,
    ):
        mock_pivot.ainvoke = AsyncMock(return_value=_pivot_output())
        result = await lateral_node(state, config)
    assert result["pivots"] == []
    mock_pivot.ainvoke.assert_not_awaited()
    mock_spawn.assert_not_awaited()
    assert result["phase"] == "cleanup"


async def test_no_candidates_is_noop(tmp_path, monkeypatch):
    """No harvested secrets → no candidates → noop.

    The loop body never runs; the returned patch carries empty
    pivots / sub_engagements / movement_paths but still advances
    ``phase="cleanup"`` and increments the iteration_count.
    """
    monkeypatch.chdir(tmp_path)
    state = _state()
    state.harvested_secrets = []
    config = _config_with_bus(None)
    with patch("autored.agents.lateral.pivotexecutor_subagent") as mock_pivot:
        mock_pivot.ainvoke = AsyncMock()
        result = await lateral_node(state, config)
    assert result["pivots"] == []
    assert result["sub_engagements"] == []
    assert result["phase"] == "cleanup"
    mock_pivot.ainvoke.assert_not_awaited()


# ---------------- pure helpers ----------------


def test_extract_username_from_source():
    """Parse the username from Phase 4's CredHarvester source strings.

    ``secretsdump:SAM/<u>`` and ``mimikatz:<provider>/<u>`` yield the
    trailing ``<u>``. Non-credential sources (file paths, ``config:``
    stub entries) yield ``""``.
    """
    assert _extract_username_from_source("secretsdump:SAM/administrator") == "administrator"
    assert _extract_username_from_source("mimikatz:msv/bob") == "bob"
    # Non-credential sources yield no username
    assert _extract_username_from_source("/etc/shadow") == ""
    assert _extract_username_from_source("config:unknown") == ""


def test_identify_pivot_candidates_targets_unfootholded_hosts():
    """Un-footholded known hosts become pivot targets.

    The state has two known hosts (.22 with a foothold, .11 without).
    The one harvested secret (a hash on .22) yields one candidate
    targeting .11 with method ``wmiexec`` (hash → wmiexec) and a
    confidence in (0.0, 0.95].
    """
    state = _state()
    cands = _identify_pivot_candidates(
        state.harvested_secrets,
        state.trust_relationships,
        state.hosts,
        {f.host_ip for f in state.footholds},
    )
    assert len(cands) == 1
    c = cands[0]
    assert c.target_host == "192.168.56.11"   # the un-footholded host
    assert c.source_host == "192.168.56.22"
    assert c.username == "administrator"
    assert c.method == "wmiexec"              # hash → wmiexec
    assert 0.0 < c.confidence <= 0.95


def test_identify_pivot_candidates_uses_trust_detail_hosts():
    """Trust.details["hosts"] surfaces new pivot targets.

    When the only known host already has a foothold (.22) but a trust
    relationship references .11 in its details, .11 still becomes a
    pivot target. This is the Phase 4 deviation: ``Trust.target`` is a
    domain/share, not an IP — pivot targets come from
    ``Trust.details["hosts"]``.
    """
    state = _state()
    state.hosts = [state.hosts[0]]  # only host 1 known
    state.trust_relationships = [
        Trust(
            host_ip="192.168.56.22",
            trust_type="ad_domain",
            target="NORTH.SOUTH.LOCAL",
            details={"hosts": ["192.168.56.11"]},
        ),
    ]
    cands = _identify_pivot_candidates(
        state.harvested_secrets,
        state.trust_relationships,
        state.hosts,
        {"192.168.56.22"},
    )
    assert len(cands) == 1
    assert cands[0].target_host == "192.168.56.11"  # from trust details


def test_max_pivots_constant():
    """Module constant bounds the number of pivots per lateral pass."""
    assert MAX_PIVOTS == 3


def test_select_pivot_method_and_confidence():
    """Pure helpers: method selection + confidence scoring.

    - ``hash`` → ``wmiexec``; base 0.7 + 0.1 (wmiexec) + 0.1 (mimikatz
      / secretsdump source) = 0.9.
    - ``password`` → ``crackmapexec``; base 0.5, no bonus (credharvester
      sources don't bump).
    - other secret types → ``None`` (skip the candidate).
    - Confidence is capped at 0.95.
    """
    hash_secret = Secret(
        host_ip="1.2.3.4",
        secret_type="hash",
        secret_value="abc",
        source="secretsdump:SAM/administrator",
    )
    assert _select_pivot_method(hash_secret) == "wmiexec"
    # 0.7 (hash) + 0.1 (wmiexec) + 0.1 (secretsdump source) = 0.9
    assert _calculate_confidence(hash_secret, "wmiexec") == pytest.approx(0.9)

    pwd_secret = Secret(
        host_ip="1.2.3.4",
        secret_type="password",
        secret_value="pwd",
        source="credharvester:manual/bob",
    )
    assert _select_pivot_method(pwd_secret) == "crackmapexec"
    # 0.5 (password), no method bonus, no source bonus
    assert _calculate_confidence(pwd_secret, "crackmapexec") == pytest.approx(0.5)

    other_secret = Secret(
        host_ip="1.2.3.4",
        secret_type="key",
        secret_value="x",
        source="/etc/shadow",
    )
    assert _select_pivot_method(other_secret) is None

    # mimikatz source bumps confidence the same way as secretsdump
    mimi_hash = Secret(
        host_ip="1.2.3.4",
        secret_type="hash",
        secret_value="abc",
        source="mimikatz:wdigest/administrator",
    )
    # 0.7 (hash) + 0.1 (wmiexec) + 0.1 (mimikatz source) = 0.9
    assert _calculate_confidence(mimi_hash, "wmiexec") == pytest.approx(0.9)
