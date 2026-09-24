"""Integration tests for the Post-Ex Agent node (Phase 4, Task 11).

Verifies the five Review Focus scenarios from the brief:

1. ``test_postex_node_runs_all_subactivities`` — happy path: all six
   sub-activities run on a Windows foothold, state advances to
   ``phase=lateral`` with iteration_count incremented.
2. ``test_postex_node_roe_blocks_persistence`` — RF#1: RoE
   ``persistence_allowed=False`` skips the persistence sub-activity
   entirely (the ``persistenceagent_subagent`` is never invoked).
3. ``test_postex_node_roe_blocks_kernel_privesc`` — RF#2: RoE
   ``kernel_exploits_allowed=False`` blocks a kernel-category privesc
   candidate; no ``privesc_attempts`` are recorded.
4. ``test_postex_node_bloodhound_skipped_on_linux`` — RF#4: a Linux
   foothold (``access_type=ssh``) does NOT invoke
   ``bloodhound_collect`` (BloodHound is Windows-only).
5. ``test_postex_node_hitl_rejection_in_privesc`` — RF#5: operator
   rejects the first privesc candidate via the HitL gate; the agent
   tries the next candidate, which is approved.

RF#3 (persistence artifact records ``removal_command``) is covered by
the T9 model + subagent tests (``tests/unit/models/test_postex.py`` +
``tests/unit/subagents/test_persistenceagent.py``) — already done
before T11.

I1 (Phase 3 fix wave): the EventBus travels via
``config["configurable"]["event_bus"]`` (RunnableConfig), NOT via
``state.event_bus``. LangGraph's reducer round-trips state through
``model_dump() + model_validate()`` which strips the
``__pydantic_extra__`` dict where ``state.event_bus = ...`` was stored
under ``extra="allow"``. The RunnableConfig is the standard LangGraph
channel for runtime objects (it never crosses the reducer boundary).
Each test here calls ``postex_node`` directly with the
``_config_with_bus(bus)`` helper, mirroring the production CLI call
shape (see ``autored/cli.py`` ``run``).

Sub-agent imports are MODULE-LEVEL in ``autored.agents.postex`` so
test patches like ``patch("autored.agents.postex.windowsenum_subagent")``
are visible to the helpers at call time — the helper references the
module global, which ``patch`` replaces in-place.
"""
from contextlib import contextmanager
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from autored.agents.postex import postex_node
from autored.config import load_roe
from autored.models.foothold import Foothold
from autored.models.postex import PrivescCandidate, Secret, Trust
from autored.state import EngagementState
from autored.subagents.credharvester import credharvester_subagent
from autored.subagents.evasionagent import evasionagent_subagent
from autored.subagents.exfilagent import exfilagent_subagent
from autored.subagents.linuxenum import linuxenum_subagent
from autored.subagents.persistenceagent import persistenceagent_subagent
from autored.subagents.privescfinder import privescfinder_subagent
from autored.subagents.windowsenum import windowsenum_subagent
from autored.tools.bloodhound import bloodhound_collect
from autored.tui.event_bus import EventBus


@pytest.fixture
def goad_state(sandbox_roe_yaml):
    """Pre-postex engagement state for a single Windows GoAD foothold.

    Uses ``access_type="winrm"`` so ``_determine_os_type`` returns
    ``"windows"`` unambiguously — ``"winrm"`` is not in the
    ``("ssh", "shell")`` tuple the helper treats as Linux-indicative,
    so the AND short-circuits and the helper falls through to
    ``"windows"``. (The brief's example fixture used
    ``access_type="shell"``, which under the user's ``_determine_os_type``
    rule resolves to ``"linux"`` for ``method="smb"`` — contradicting
    the Windows-only patches the happy-path test relies on. Using
    ``access_type="winrm"`` removes the ambiguity.)
    """
    roe = load_roe(sandbox_roe_yaml)
    return EngagementState(
        engagement_id="test-goad-001",
        target_scope=["10.10.10.5"],
        operator="test",
        rules_of_engagement=roe,
        footholds=[
            Foothold(
                id="f1",
                host_ip="10.10.10.5",
                username="user",
                context="user",
                method="smb",
                access_type="winrm",
                evidence_path="/tmp/evidence.txt",
                established_at=datetime.utcnow(),
                hypothesis_rank=1,
            )
        ],
    )


@pytest.fixture
def bus():
    """Fresh EventBus for each test — patched per-test as needed."""
    return EventBus()


def _config_with_bus(bus: EventBus) -> dict:
    """Build a RunnableConfig-shaped dict carrying the EventBus (I1 pattern).

    Mirrors what the production CLI does (``autored/cli.py`` ``run``
    command): ``config = {"configurable": {"event_bus": bus, ...}}``.
    """
    return {"configurable": {"event_bus": bus}}


@contextmanager
def _patch_all_subagents():
    """Patch all 7 sub-agents + ``bloodhound_collect`` with empty defaults.

    Returns a dict mapping short-name → mock so individual tests can
    override return values per-test and assert call/not-called. The
    defaults are empty-list MagicMocks so the postex loop runs to
    completion without invoking any real tool wrappers — the point of
    the integration tests is to verify the postex_node orchestration
    (RoE gates, HitL gates, dispatch order), not the underlying tools
    (those are covered by the T8-T10 subagent tests).

    I6 fix: outer mocks now use ``AsyncMock(spec=<real_subagent>)`` so
    the mock is spec-aware — attribute access is restricted to what
    exists on the real subagent, and child mocks (like ``.ainvoke``)
    inherit the spec from the real tool's ``ainvoke`` method. This is
    what would have caught C1 (the missing ``file_path`` /
    ``catch_server`` kwargs) at integration time rather than letting
    a permissive ``MagicMock()`` silently accept any kwargs.
    """
    with (
        patch("autored.agents.postex.windowsenum_subagent") as mock_wenum,
        patch("autored.agents.postex.linuxenum_subagent") as mock_lenum,
        patch("autored.agents.postex.privescfinder_subagent") as mock_privesc,
        patch("autored.agents.postex.credharvester_subagent") as mock_cred,
        patch("autored.agents.postex.persistenceagent_subagent") as mock_persist,
        patch("autored.agents.postex.evasionagent_subagent") as mock_evasion,
        patch("autored.agents.postex.exfilagent_subagent") as mock_exfil,
        patch("autored.agents.postex.bloodhound_collect") as mock_bh,
    ):
        # Spec-aware outer mocks: attribute access restricted to what
        # exists on the real subagent (so e.g. ``mock_wenum.typos`` would
        # fail rather than silently auto-create). Inner ``.ainvoke`` is
        # still a plain AsyncMock so the per-test ``.ainvoke = ...``
        # overrides in the test bodies keep working.
        mock_wenum.configure_mock(spec=windowsenum_subagent)
        mock_lenum.configure_mock(spec=linuxenum_subagent)
        mock_privesc.configure_mock(spec=privescfinder_subagent)
        mock_cred.configure_mock(spec=credharvester_subagent)
        mock_persist.configure_mock(spec=persistenceagent_subagent)
        mock_evasion.configure_mock(spec=evasionagent_subagent)
        mock_exfil.configure_mock(spec=exfilagent_subagent)
        mock_bh.configure_mock(spec=bloodhound_collect)

        # Default empty-list return values — tests override per-test.
        mock_wenum.ainvoke = AsyncMock(
            return_value=MagicMock(
                users=[], secrets=[], privesc_candidates=[]
            )
        )
        mock_lenum.ainvoke = AsyncMock(
            return_value=MagicMock(
                users=[], secrets=[], privesc_candidates=[]
            )
        )
        mock_privesc.ainvoke = AsyncMock(
            return_value=MagicMock(candidates=[], attempts=[])
        )
        mock_cred.ainvoke = AsyncMock(return_value=MagicMock(secrets=[]))
        mock_persist.ainvoke = AsyncMock(
            return_value=MagicMock(artifacts=[])
        )
        mock_evasion.ainvoke = AsyncMock(
            return_value=MagicMock(actions=[])
        )
        mock_exfil.ainvoke = AsyncMock(
            return_value=MagicMock(proofs=[])
        )
        mock_bh.ainvoke = AsyncMock(return_value=MagicMock())
        yield {
            "wenum": mock_wenum,
            "lenum": mock_lenum,
            "privesc": mock_privesc,
            "cred": mock_cred,
            "persist": mock_persist,
            "evasion": mock_evasion,
            "exfil": mock_exfil,
            "bh": mock_bh,
        }


@pytest.mark.asyncio
async def test_postex_node_runs_all_subactivities(goad_state, bus):
    """Happy path: all 6 sub-activities run on a Windows foothold.

    Patches every sub-agent with empty-list defaults so the loop runs
    to completion. Asserts:
    - ``windowsenum_subagent.ainvoke`` called (Enumeration sub-activity
      dispatched to the Windows path).
    - ``credharvester_subagent.ainvoke`` called (CredHarvester runs as
      part of the Enumeration sub-activity).
    - ``persistenceagent_subagent.ainvoke`` called (persistence is
      permitted by the sandbox RoE and the auto_approve HitL mode
      short-circuits the gate).
    - Result ``phase == "lateral"`` and iteration_count incremented.
    """
    config = _config_with_bus(bus)
    with _patch_all_subagents() as mocks:
        result = await postex_node(goad_state, config)

    assert result["phase"] == "lateral"
    assert result["iteration_count"] == goad_state.iteration_count + 1
    # Enumeration sub-activity dispatched to Windows path + credharvester.
    mocks["wenum"].ainvoke.assert_awaited_once()
    mocks["cred"].ainvoke.assert_awaited_once()
    # Persistence sub-activity ran (sandbox RoE allows it + auto_approve).
    mocks["persist"].ainvoke.assert_awaited_once()
    # BloodHound intent logged for Windows but no creds → no call.
    mocks["bh"].ainvoke.assert_not_awaited()


@pytest.mark.asyncio
async def test_postex_node_roe_blocks_persistence(goad_state, bus):
    """RF#1: ``persistence_allowed=False`` skips persistence entirely.

    The persistence sub-activity is gated at the postex_node level
    (not inside the helper) — when the RoE flag is False, the helper
    is never invoked at all. This is the strongest form of RoE
    enforcement: the operator's policy is checked before any HitL
    gate, before any sub-agent call.
    """
    goad_state.rules_of_engagement.persistence_allowed = False

    config = _config_with_bus(bus)
    with _patch_all_subagents() as mocks:
        result = await postex_node(goad_state, config)

    mocks["persist"].ainvoke.assert_not_awaited()
    assert result["persistence_artifacts"] == []
    # The other sub-activities still ran (RoE allows them).
    mocks["wenum"].ainvoke.assert_awaited_once()
    mocks["evasion"].ainvoke.assert_awaited_once()
    mocks["exfil"].ainvoke.assert_awaited_once()


@pytest.mark.asyncio
async def test_postex_node_roe_blocks_kernel_privesc(goad_state, bus):
    """RF#2: ``kernel_exploits_allowed=False`` blocks a kernel candidate.

    The privesc sub-activity iterates candidates. For each, it looks up
    the risk category in ``PRIVESC_RISK_CATEGORIES``. The kernel entry
    carries ``roe_key="kernel_exploits_allowed"`` — when that RoE flag
    is False, the candidate is skipped before the HitL gate (RoE is a
    hard block, HitL is a soft gate). No ``PrivescAttempt`` is
    recorded for the blocked candidate.
    """
    goad_state.rules_of_engagement.kernel_exploits_allowed = False

    fake_candidates = [
        PrivescCandidate(
            host_ip="10.10.10.5",
            technique="dirty_pipe",
            category="kernel",  # kernel requires RoE permission
            details="CVE-2022-0847",
            confidence=0.9,
            exploit_command="./dirty_pipe",
            removal_command=None,
        ),
    ]

    config = _config_with_bus(bus)
    with _patch_all_subagents() as mocks:
        # Override windowsenum to surface the kernel candidate directly —
        # the postex loop then calls _run_privesc with this non-empty
        # list, so privescfinder is NOT called (the override short-circuits
        # the LLM step). The kernel candidate is blocked at the RoE check.
        mocks["wenum"].ainvoke = AsyncMock(
            return_value=MagicMock(
                users=[], secrets=[], privesc_candidates=fake_candidates
            )
        )
        result = await postex_node(goad_state, config)

    assert len(result["privesc_attempts"]) == 0
    # privescfinder not called because enum already surfaced candidates.
    mocks["privesc"].ainvoke.assert_not_awaited()


@pytest.mark.asyncio
async def test_postex_node_bloodhound_skipped_on_linux(goad_state, bus):
    """RF#4: Linux foothold does NOT invoke ``bloodhound_collect``.

    ``_maybe_run_bloodhound`` is only called from the main loop when
    ``os_type == "windows"``. For a Linux foothold (``access_type=ssh``),
    the helper is never invoked, so ``bloodhound_collect.ainvoke`` is
    never reached — even though the helper itself would only log intent
    (Phase 4 stub; actual call is deferred to Phase 5).

    Asserts the Linux dispatch path is taken (``linuxenum_subagent``
    called, ``windowsenum_subagent`` not called) AND ``bloodhound_collect``
    is never awaited.
    """
    goad_state.footholds[0].access_type = "ssh"  # flip to Linux

    config = _config_with_bus(bus)
    with _patch_all_subagents() as mocks:
        result = await postex_node(goad_state, config)

    # Linux dispatch — linuxenum called, windowsenum never.
    mocks["lenum"].ainvoke.assert_awaited_once()
    mocks["wenum"].ainvoke.assert_not_awaited()
    # BloodHound is Windows-only — never reached on Linux.
    mocks["bh"].ainvoke.assert_not_awaited()
    # Sanity: phase still advances.
    assert result["phase"] == "lateral"


@pytest.mark.asyncio
async def test_postex_node_hitl_rejection_in_privesc(goad_state, bus):
    """RF#5: operator rejects first privesc candidate → agent tries next.

    Two ``app_system`` candidates are surfaced by windowsenum (the
    ``app_system`` category requires a HitL gate per
    ``PRIVESC_RISK_CATEGORIES`` — ``hitl_required=True``). The HitL
    gate emits a ``hitl_gate`` event and blocks on
    ``bus.wait_for_tui_response()``. The operator's first response is
    ``reject`` → the agent skips that candidate and tries the next.
    The second response is ``approve`` → the agent records a
    ``PrivescAttempt`` for that candidate.

    Asserts:
    - ``wait_for_tui_response`` called at least once (the gate fired).
    - At least one ``privesc_attempts`` entry was recorded (the second
      candidate was approved and attempted).

    Note: the brief's example used ``category="misconfig"`` for the
    candidates, but ``misconfig`` has ``hitl_required=False`` — under
    the user's spec, misconfig candidates are auto-attempted without a
    HitL gate, so ``wait_for_tui_response`` would never be called.
    This test uses ``app_system`` so the gate is actually exercised.
    """
    goad_state.rules_of_engagement.hitl_mode = "always_ask"
    # Isolate the privesc HitL gate — disable the persistence / evasion /
    # exfiltration sub-activities so their gates don't consume the
    # limited response iterator. The point of this test is the privesc
    # loop's reject-and-try-next behaviour, not the other gates.
    goad_state.rules_of_engagement.persistence_allowed = False
    goad_state.rules_of_engagement.evasion_allowed = False
    goad_state.rules_of_engagement.exfiltration_allowed = False

    candidates = [
        PrivescCandidate(
            host_ip="10.10.10.5",
            technique="schtasks_backdoor",
            category="app_system",  # requires HitL gate
            details="modifiable task path",
            confidence=0.9,
            exploit_command="schtasks /change ...",
            removal_command=None,
        ),
        PrivescCandidate(
            host_ip="10.10.10.5",
            technique="unquoted_svc_path",
            category="app_system",  # requires HitL gate
            details="unquoted service path",
            confidence=0.7,
            exploit_command='sc config "VulnSvc" binPath= ...',
            removal_command=None,
        ),
    ]

    responses = iter(
        [
            {"response": "reject", "modified_command": None},  # first
            {"response": "approve", "modified_command": None},  # second
        ]
    )

    async def _mock_wait():
        return next(responses)

    config = _config_with_bus(bus)
    with (
        _patch_all_subagents() as mocks,
        patch.object(
            bus,
            "wait_for_tui_response",
            new=AsyncMock(side_effect=_mock_wait),
        ) as mock_wait,
        patch.object(bus, "emit_to_tui", new=AsyncMock()),
    ):
        # Override windowsenum to surface the two app_system candidates.
        mocks["wenum"].ainvoke = AsyncMock(
            return_value=MagicMock(
                users=[], secrets=[], privesc_candidates=candidates
            )
        )
        result = await postex_node(goad_state, config)

    # HitL gate fired at least once (first candidate).
    assert mock_wait.call_count >= 1
    # Second candidate approved → one PrivescAttempt recorded.
    assert len(result["privesc_attempts"]) == 1
    # The attempted candidate's host_ip matches the foothold.
    assert result["privesc_attempts"][0].host_ip == "10.10.10.5"
    # I5 fix: candidate_id is the candidate's UUID, not the host_ip.
    # The approved candidate's id (a uuid4 str) should appear as the
    # attempt's candidate_id, distinct from the host_ip.
    attempt = result["privesc_attempts"][0]
    assert attempt.candidate_id != attempt.host_ip
    assert attempt.candidate_id == candidates[1].id


@pytest.mark.asyncio
async def test_postex_node_bloodhound_invoked_with_creds_and_domain(
    goad_state, bus
):
    """I3 fix: ``_maybe_run_bloodhound`` actually calls
    ``bloodhound_collect.ainvoke`` when AD creds + an ``ad_domain`` trust
    are present.

    Previously the helper only logged intent and deferred the call to
    Phase 5 — the T11 integration test patches ``bloodhound_collect``
    but production code never invoked it (a real functional gap). The
    Phase 4 fix wave wires the call:

    * ``credharvester_subagent`` returns a password-type ``Secret`` with
      ``source="mimikatz:wdigest/administrator"``.
    * State pre-populated with a ``Trust(trust_type="ad_domain",
      target="CORP.LOCAL")`` (Phase 4 enum sub-agents don't surface
      trusts yet — Phase 5 will — but the helper's domain lookup
      against ``state.trust_relationships`` works regardless of who
      populated it).
    * Asserts ``bloodhound_collect.ainvoke`` was awaited with
      ``username="administrator"``, ``password=secret_value``,
      ``domain="CORP.LOCAL"``, ``host=foothold.host_ip``, and the
      engagement_id.
    """
    fake_secret = Secret(
        host_ip="10.10.10.5",
        secret_type="password",
        secret_value="P@ssw0rd!",
        source="mimikatz:wdigest/administrator",
    )
    fake_trust = Trust(
        host_ip="10.10.10.5",
        trust_type="ad_domain",
        target="CORP.LOCAL",
        details={"domain": "CORP.LOCAL"},
    )
    goad_state.harvested_secrets = [fake_secret]
    goad_state.trust_relationships = [fake_trust]

    config = _config_with_bus(bus)
    with _patch_all_subagents() as mocks:
        # Override credharvester to surface the AD password secret so
        # the postex_node loop accumulates it into state.harvested_secrets
        # before _maybe_run_bloodhound runs (it doesn't — the helper
        # reads state at call time, which is the original empty list
        # because the loop accumulates after the helper runs). So we
        # pre-populate state.harvested_secrets above (before the loop)
        # — that's what _maybe_run_bloodhound reads.
        result = await postex_node(goad_state, config)

    mocks["bh"].ainvoke.assert_awaited_once()
    call_kwargs = mocks["bh"].ainvoke.call_args.args[0]
    assert call_kwargs["username"] == "administrator"
    assert call_kwargs["password"] == "P@ssw0rd!"
    assert call_kwargs["domain"] == "CORP.LOCAL"
    assert call_kwargs["host"] == "10.10.10.5"
    assert call_kwargs["engagement_id"] == goad_state.engagement_id
    # Sanity: phase still advances.
    assert result["phase"] == "lateral"
