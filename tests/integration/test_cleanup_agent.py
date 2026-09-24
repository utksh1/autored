"""Integration tests for the Cleanup Agent node (Phase 5 Task 12).

Direct-node-entry pattern (same as ``tests/integration/test_lateral_agent.py``):
construct an ``EngagementState``, patch the sub-agent @tool entrypoints at
their ``autored.agents.cleanup`` aliases, call ``cleanup_node`` directly
with a ``RunnableConfig``-shaped dict, and assert the returned state-dict
patch.

I1 (Phase 3 fix wave): the EventBus travels via
``config["configurable"]["event_bus"]`` (RunnableConfig), NOT via
``state.event_bus``. LangGraph's reducer round-trips state through
``model_dump() + model_validate()`` which strips the
``__pydantic_extra__`` dict where ``state.event_bus = ...`` was stored
under ``extra="allow"``. The RunnableConfig is the standard LangGraph
channel for runtime objects (it never crosses the reducer boundary).
Each test here calls ``cleanup_node`` directly with the
``_config_with_bus(bus)`` helper, mirroring the production CLI call shape
(see ``autored/cli.py`` ``run``).

Sub-agent imports are MODULE-LEVEL in ``autored.agents.cleanup`` so test
patches like ``patch("autored.agents.cleanup.artifactremover_subagent")``
are visible to the helper bodies at call time — the helpers reference the
module globals, which ``patch`` replaces in-place.
"""
from unittest.mock import AsyncMock, patch

from autored.agents.cleanup import (
    _creds_for_host,
    _generate_cleanup_plan,
    _identify_temp_files,
    cleanup_node,
)
from autored.models.cleanup import CleanupResult
from autored.models.lateral import TunnelConfig
from autored.models.postex import PersistenceArtifact, Secret
from autored.models.roe import RulesOfEngagement
from autored.state import EngagementState
from autored.subprocess_runner import SubprocessResult
from autored.tui.event_bus import EventBus


def _roe(hitl_mode="auto_approve") -> RulesOfEngagement:
    return RulesOfEngagement(
        engagement_name="t",
        operator="op",
        operator_signature="s",
        allowed_ips=["0.0.0.0/0"],
        allowed_techniques=["*"],
        persistence_allowed=True,
        evasion_allowed=True,
        exfiltration_allowed=True,
        kernel_exploits_allowed=True,
        hitl_mode=hitl_mode,
    )


def _state(hitl_mode="auto_approve") -> EngagementState:
    s = EngagementState(
        engagement_id="eng-1",
        target_scope=["192.168.56.22"],
        operator="op",
        rules_of_engagement=_roe(hitl_mode),
    )
    s.persistence_artifacts = [
        PersistenceArtifact(
            id="a-1",
            host_ip="192.168.56.22",
            method="scheduled_task",
            details={
                "task_name": "AutoRedUpdate",
                "command": "powershell -enc x",
            },
            removal_command="schtasks /delete /tn AutoRedUpdate /f",
            foothold_id="f-1",
        ),
        PersistenceArtifact(
            id="a-2",
            host_ip="192.168.56.22",
            method="registry_run",
            details={
                "key_path": (
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                ),
                "value_name": "AutoRed",
            },
            removal_command="reg delete HKCU\\...\\Run /v AutoRed /f",
            foothold_id="f-1",
        ),
    ]
    s.tunnels = [
        TunnelConfig(
            tool="chisel",
            proxy_endpoint="10.10.14.5:1080",
            local_port=1080,
            target_network="0.0.0.0/0",
            teardown_command="pkill -f 'chisel client 10.10.14.5:1080'",
        ),
    ]
    s.harvested_secrets = [
        Secret(
            host_ip="192.168.56.22",
            secret_type="hash",
            secret_value="abc123",
            source="secretsdump:SAM/administrator",
        ),
    ]
    return s


def _remover_output(success=True):
    """Two CleanupResults mimicking ArtifactRemoverOutput.results."""
    from autored.subagents.artifactremover import ArtifactRemoverOutput

    err = None if success else "STATUS_LOGON_FAILURE"
    return ArtifactRemoverOutput(
        results=[
            CleanupResult(
                artifact_id="a-1",
                host_ip="192.168.56.22",
                removal_command="r1",
                success=success,
                verified=False,
                error=err,
            ),
            CleanupResult(
                artifact_id="a-2",
                host_ip="192.168.56.22",
                removal_command="r2",
                success=success,
                verified=False,
                error=err,
            ),
        ]
    )


def _scanner_output(verified=True):
    """Two CleanupResults mimicking VerificationScannerOutput.results."""
    from autored.subagents.verificationscanner import VerificationScannerOutput

    err = None if verified else "artifact still present"
    return VerificationScannerOutput(
        results=[
            CleanupResult(
                artifact_id="a-1",
                host_ip="192.168.56.22",
                removal_command="v1",
                success=True,
                verified=verified,
                error=err,
            ),
            CleanupResult(
                artifact_id="a-2",
                host_ip="192.168.56.22",
                removal_command="v2",
                success=True,
                verified=verified,
                error=err,
            ),
        ]
    )


def _config_with_bus(bus) -> dict:
    """Build a RunnableConfig-shaped dict carrying the EventBus (I1 pattern).

    Mirrors what the production CLI does (``autored/cli.py`` ``run``
    command): ``config = {"configurable": {"event_bus": bus, ...}}``.
    Passing ``bus=None`` simulates a headless ``--no-tui`` run.
    """
    return {"configurable": {"event_bus": bus}}


def _teardown_subprocess_result() -> SubprocessResult:
    """SubprocessResult returned by the local ``run_subprocess`` mock."""
    return SubprocessResult(
        stdout="",
        stderr="",
        returncode=0,
        duration_sec=0.1,
        command="pkill",
    )


async def test_happy_path_removes_and_verifies(tmp_path, monkeypatch):
    """Happy path: plan → auto-approve → per-host removal + verification.

    Asserts:
    - phase advances to ``report``; iteration_count incremented.
    - 5 cleanup_results = 1 tunnel teardown + 2 removals + 2 verifications.
    - 3 verified = 1 tunnel teardown + 2 successful re-scans.
    - ArtifactRemover got the host plan dict with creds from
      harvested secrets (``username="administrator"``,
      ``nthash="abc123"``) and the 2 artifact dicts.
    - Tunnel teardown was run locally via ``run_subprocess`` (the
      ``["sh", "-c", teardown]`` invocation pattern).
    """
    monkeypatch.chdir(tmp_path)
    state = _state()
    config = _config_with_bus(None)
    with (
        patch("autored.agents.cleanup.artifactremover_subagent") as mock_rm,
        patch("autored.agents.cleanup.verificationscanner_subagent") as mock_scan,
        patch(
            "autored.agents.cleanup.run_subprocess",
            new=AsyncMock(return_value=_teardown_subprocess_result()),
        ) as mock_run,
    ):
        mock_rm.ainvoke = AsyncMock(return_value=_remover_output())
        mock_scan.ainvoke = AsyncMock(return_value=_scanner_output())
        result = await cleanup_node(state, config)

    assert result["phase"] == "report"
    assert result["iteration_count"] == state.iteration_count + 1
    # 1 tunnel teardown + 2 removals + 2 verifications (spec §6.6)
    assert len(result["cleanup_results"]) == 5
    verified = [r for r in result["cleanup_results"] if r.verified]
    # 1 tunnel teardown + 2 verified re-scans
    assert len(verified) == 3
    # Both sub-agents got the host plan with creds from harvested secrets
    # (LangChain @tool invocation pattern — single positional dict arg,
    # same shape lateral_node uses for pivotexecutor_subagent).
    invoke_input = mock_rm.ainvoke.call_args.args[0]
    plan_arg = invoke_input["host_plan"]
    assert plan_arg["username"] == "administrator"
    assert plan_arg["nthash"] == "abc123"
    artifacts_arg = invoke_input["artifacts"]
    assert len(artifacts_arg) == 2
    # Tunnel teardown ran locally via the ["sh", "-c", ...] pattern
    teardown_calls = [
        c for c in mock_run.call_args_list
        if "pkill" in str(c)
    ]
    assert teardown_calls


async def test_gate_rejection_executes_nothing(tmp_path, monkeypatch):
    """Review Focus #4: operator rejects the cleanup plan → zero removal
    commands, zero cleanup_results, phase still advances to report.

    The bus is pre-loaded with a ``{"approved": False}`` response so
    ``bus.wait_for_tui_response()`` returns it immediately. The
    ``_hitl_cleanup_gate`` returns ``False``; the node short-circuits
    with ``phase="report"`` and zero cleanup_results. None of the
    sub-agents or the local ``run_subprocess`` are awaited.
    """
    monkeypatch.chdir(tmp_path)
    state = _state(hitl_mode="always_ask")
    bus = EventBus()
    await bus.emit_to_orchestrator({"type": "hitl_response", "approved": False})
    config = _config_with_bus(bus)
    with (
        patch("autored.agents.cleanup.artifactremover_subagent") as mock_rm,
        patch("autored.agents.cleanup.verificationscanner_subagent") as mock_scan,
        patch(
            "autored.agents.cleanup.run_subprocess",
            new=AsyncMock(),
        ) as mock_run,
    ):
        mock_rm.ainvoke = AsyncMock()
        mock_scan.ainvoke = AsyncMock()
        result = await cleanup_node(state, config)
    assert result["phase"] == "report"
    assert result["cleanup_results"] == []
    mock_rm.ainvoke.assert_not_awaited()
    mock_scan.ainvoke.assert_not_awaited()
    mock_run.assert_not_awaited()


async def test_failed_removal_visible_in_results(tmp_path, monkeypatch):
    """Review Focus #5: removal fails + verification says still present →
    unverified results with errors survive into the final state.

    The ArtifactRemover returns two ``success=False, verified=False``
    CleanupResults with ``error="STATUS_LOGON_FAILURE"``. The
    VerificationScanner returns two ``verified=False`` CleanupResults
    with ``error="artifact still present"``. Both surface into
    ``cleanup_results`` — never silently green. The 5th entry is the
    locally-verified tunnel teardown (``success=True, verified=True``).
    """
    monkeypatch.chdir(tmp_path)
    state = _state()
    config = _config_with_bus(None)
    with (
        patch("autored.agents.cleanup.artifactremover_subagent") as mock_rm,
        patch("autored.agents.cleanup.verificationscanner_subagent") as mock_scan,
        patch(
            "autored.agents.cleanup.run_subprocess",
            new=AsyncMock(return_value=_teardown_subprocess_result()),
        ),
    ):
        mock_rm.ainvoke = AsyncMock(return_value=_remover_output(success=False))
        mock_scan.ainvoke = AsyncMock(
            return_value=_scanner_output(verified=False)
        )
        result = await cleanup_node(state, config)
    assert len(result["cleanup_results"]) == 5
    # tunnel teardown is locally verified; all 4 artifact results unverified
    unverified = [r for r in result["cleanup_results"] if not r.verified]
    assert len(unverified) == 4
    assert all(r.error is not None for r in unverified)


async def test_empty_state_is_noop(tmp_path, monkeypatch):
    """No artifacts, no tunnels, no temp files → noop.

    The plan is empty (zero host plans, zero total_actions); the loop
    body never runs. The returned patch carries empty cleanup_results
    but still advances to ``phase="report"`` and increments
    iteration_count. None of the sub-agents are awaited.
    """
    monkeypatch.chdir(tmp_path)
    state = _state()
    state.persistence_artifacts = []
    state.tunnels = []
    config = _config_with_bus(None)
    with patch(
        "autored.agents.cleanup.artifactremover_subagent"
    ) as mock_rm:
        mock_rm.ainvoke = AsyncMock()
        result = await cleanup_node(state, config)
    assert result["phase"] == "report"
    assert result["cleanup_results"] == []
    mock_rm.ainvoke.assert_not_awaited()


# ---------------- pure helpers ----------------


def test_identify_temp_files_filters_staged_tools_only():
    """``_identify_temp_files`` picks staged tool binaries / staging
    zips out of evidence paths — never raw tool output or evidence
    deliverables.

    Substring match (case-insensitive) on the path's basename for the
    four markers: ``linpeas``, ``winpeas``, ``bloodhound``,
    ``mimikatz``. Raw nmap output and PNG screenshots are NEVER
    deleted by cleanup (engagement deliverables).
    """
    paths = [
        "engagements/e1/raw/nmap_123.out",          # evidence — KEEP
        "engagements/e1/evidence/screenshot.png",   # evidence — KEEP
        "engagements/e1/raw/linpeas_upload.sh",     # staged tool — delete
        "engagements/e1/raw/winpeas.exe",          # staged tool — delete
        "engagements/e1/evidence/bloodhound.zip",   # staging zip — delete
    ]
    temp = _identify_temp_files(paths)
    assert "engagements/e1/raw/linpeas_upload.sh" in temp
    assert "engagements/e1/raw/winpeas.exe" in temp
    assert "engagements/e1/evidence/bloodhound.zip" in temp
    assert "engagements/e1/raw/nmap_123.out" not in temp
    assert "engagements/e1/evidence/screenshot.png" not in temp


def test_generate_cleanup_plan_groups_by_host_with_creds():
    """Plan groups all cleanup actions per host, attaches credentials
    from harvested secrets to real host plans.

    Three host plans:
    1. The real host (``192.168.56.22``) — artifact_ids +
       removal_commands + the engagement's harvested creds.
    2. A ``tunnel:<endpoint>`` pseudo-host — teardowns only (no creds;
       teardowns run locally on the AutoRed host).
    3. ``local:tmp`` — temp files only (no creds).

    ``total_actions`` sums removals + teardowns + temp files across
    every host plan.
    """
    state = _state()
    plan = _generate_cleanup_plan(
        state.persistence_artifacts,
        state.tunnels,
        ["engagements/e1/raw/linpeas_upload.sh"],
        state.harvested_secrets,
    )
    assert len(plan.by_host) == 3  # real host + tunnel pseudo-host + local:tmp

    # Real host: artifacts + creds (no teardowns, no temp files on it)
    host_plan = plan.by_host[0]  # insertion order: real host first
    assert host_plan.host_ip == "192.168.56.22"
    assert host_plan.artifact_ids == ["a-1", "a-2"]
    assert len(host_plan.removal_commands) == 2
    assert host_plan.username == "administrator"
    assert host_plan.nthash == "abc123"

    # Tunnel pseudo-host: teardowns only, no creds
    tunnel_plan = plan.by_host[1]
    assert tunnel_plan.host_ip.startswith("tunnel:")
    assert tunnel_plan.tunnel_teardowns == [
        "pkill -f 'chisel client 10.10.14.5:1080'",
    ]
    assert tunnel_plan.username == ""

    # Local tmp host: temp files only, no creds
    local_plan = plan.by_host[2]
    assert local_plan.host_ip == "local:tmp"
    assert local_plan.temp_files == ["engagements/e1/raw/linpeas_upload.sh"]
    assert local_plan.username == ""

    assert plan.total_actions == 4  # 2 removals + 1 teardown + 1 temp file


def test_creds_for_host_returns_first_usable_triple():
    """``_creds_for_host`` returns the first secret whose source encodes
    a username (``"/" in source``) for the given host_ip.

    Hashes → ``nthash`` populated, ``password=""``; passwords →
    ``password`` populated, ``nthash=""``. Secrets for other hosts or
    sources without a ``/`` are skipped. A host with no usable secret
    yields empty strings (the sub-agent will fail with a clear auth
    error rather than silently binding as a wrong user).
    """
    secrets = [
        Secret(
            host_ip="1.2.3.4",
            secret_type="hash",
            secret_value="aaa",
            source="/etc/shadow",  # no "/" → no username parseable
        ),
        Secret(
            host_ip="192.168.56.22",
            secret_type="hash",
            secret_value="abc123",
            source="secretsdump:SAM/administrator",
        ),
        Secret(
            host_ip="192.168.56.22",
            secret_type="password",
            secret_value="Password1!",
            source="credharvester:manual/bob",
        ),
    ]
    creds = _creds_for_host("192.168.56.22", secrets)
    # First match wins — the hash secret
    assert creds["username"] == "administrator"
    assert creds["nthash"] == "abc123"
    assert creds["password"] == ""
    # Different host
    creds_other = _creds_for_host("9.9.9.9", secrets)
    assert creds_other["username"] == ""
    assert creds_other["password"] == ""
    assert creds_other["nthash"] == ""
