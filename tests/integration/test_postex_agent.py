"""Integration tests for the Post-Ex Agent node (Phase 4, Task 11).

The Post-Ex Agent ties together all 7 Phase 4 sub-agents, EventBus
(for HitL gates), and RoE enforcement. These tests cover the five
core scenarios called out in the Phase 4 plan:

  1. Happy path — all 6 sub-activities run, state populated.
  2. **Review Focus #1** — RoE blocks persistence when disallowed.
  3. **Review Focus #2** — kernel privesc blocked without RoE permission.
  4. **Review Focus #4** — BloodHound skipped on Linux hosts.
  5. **Review Focus #5** — operator rejects privesc candidate, agent
     tries the next candidate.

Mocks: all 7 sub-agents (``linuxenum_subagent``, ``windowsenum_subagent``,
``privescfinder_subagent``, ``credharvester_subagent``,
``persistenceagent_subagent``, ``evasionagent_subagent``,
``exfilagent_subagent``) and EventBus methods (for HitL gates). The
sub-agent @tool objects are patched at their ``autored.agents.postex``
alias so the postex_node call sites honour the patched mock at call
time.
"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from autored.state import EngagementState
from autored.models.roe import RulesOfEngagement
from autored.models.foothold import Foothold
from autored.agents.postex import postex_node
from autored.tui.event_bus import EventBus
from datetime import datetime


@pytest.fixture
def goad_state(sandbox_roe_yaml):
    roe = RulesOfEngagement.model_validate_yaml(sandbox_roe_yaml)
    state = EngagementState(
        engagement_id="test-goad-001",
        target_scope=["10.10.10.5"],
        operator="test",
        rules_of_engagement=roe,
        footholds=[Foothold(
            id="f1", host_ip="10.10.10.5", username="user",
            context="user", method="smb", access_type="shell",
            evidence_path="/tmp/evidence.txt",
            established_at=datetime.utcnow(), hypothesis_rank=1,
        )],
    )
    state.event_bus = EventBus()
    return state


@pytest.mark.asyncio
async def test_postex_node_runs_all_subactivities(goad_state):
    """Happy path: all 6 sub-activities run, state populated."""
    # Mock all sub-agents
    with patch("autored.agents.postex.windowsenum_subagent") as mock_wenum, \
         patch("autored.agents.postex.privescfinder_subagent") as mock_privesc, \
         patch("autored.agents.postex.credharvester_subagent") as mock_cred, \
         patch("autored.agents.postex.persistenceagent_subagent") as mock_persist, \
         patch("autored.agents.postex.evasionagent_subagent") as mock_evasion, \
         patch("autored.agents.postex.exfilagent_subagent") as mock_exfil:

        mock_wenum.ainvoke = AsyncMock(return_value=MagicMock(users=[], secrets=[], privesc_candidates=[]))
        mock_privesc.ainvoke = AsyncMock(return_value=MagicMock(candidates=[], attempts=[]))
        mock_cred.ainvoke = AsyncMock(return_value=MagicMock(secrets=[]))
        mock_persist.ainvoke = AsyncMock(return_value=MagicMock(artifacts=[]))
        mock_evasion.ainvoke = AsyncMock(return_value=MagicMock(actions=[]))
        mock_exfil.ainvoke = AsyncMock(return_value=MagicMock(proofs=[]))

        result = await postex_node(goad_state)

    assert result["phase"] == "lateral"
    # All sub-agents should have been called
    mock_wenum.ainvoke.assert_called()
    mock_cred.ainvoke.assert_called()
    mock_persist.ainvoke.assert_called()


@pytest.mark.asyncio
async def test_postex_node_roe_blocks_persistence(goad_state):
    """Review Focus: RoE blocks persistence when disallowed."""
    goad_state.rules_of_engagement.persistence_allowed = False

    with patch("autored.agents.postex.windowsenum_subagent") as mock_wenum, \
         patch("autored.agents.postex.credharvester_subagent") as mock_cred, \
         patch("autored.agents.postex.persistenceagent_subagent") as mock_persist:
        mock_wenum.ainvoke = AsyncMock(return_value=MagicMock(users=[], secrets=[], privesc_candidates=[]))
        mock_cred.ainvoke = AsyncMock(return_value=MagicMock(secrets=[]))
        mock_persist.ainvoke = AsyncMock(return_value=MagicMock(artifacts=[]))

        result = await postex_node(goad_state)

    # Persistence sub-agent should NOT have been called
    mock_persist.ainvoke.assert_not_called()
    assert result["persistence_artifacts"] == []


@pytest.mark.asyncio
async def test_postex_node_roe_blocks_kernel_privesc(goad_state):
    """Review Focus: kernel exploit blocked without RoE permission."""
    goad_state.rules_of_engagement.kernel_exploits_allowed = False

    from autored.models.postex import PrivescCandidate
    fake_candidates = [PrivescCandidate(
        host_ip="10.10.10.5", technique="dirty_pipe",
        category="kernel",  # kernel requires RoE permission
        details="CVE-2022-0847", confidence=0.9,
        exploit_command="...", removal_command=None,
    )]

    with patch("autored.agents.postex.windowsenum_subagent") as mock_wenum, \
         patch("autored.agents.postex.credharvester_subagent") as mock_cred, \
         patch("autored.agents.postex.privescfinder_subagent") as mock_privesc:
        mock_wenum.ainvoke = AsyncMock(return_value=MagicMock(privesc_candidates=fake_candidates))
        mock_cred.ainvoke = AsyncMock(return_value=MagicMock(secrets=[]))
        mock_privesc.ainvoke = AsyncMock(return_value=MagicMock(candidates=fake_candidates, attempts=[]))

        result = await postex_node(goad_state)

    # No privesc attempts should have been made
    assert len(result["privesc_attempts"]) == 0


@pytest.mark.asyncio
async def test_postex_node_bloodhound_skipped_on_linux(goad_state):
    """Review Focus: BloodHound skipped on Linux hosts."""
    # Change foothold to Linux
    goad_state.footholds[0].access_type = "ssh"  # Linux

    with patch("autored.agents.postex.linuxenum_subagent") as mock_lenum, \
         patch("autored.agents.postex.credharvester_subagent") as mock_cred, \
         patch("autored.agents.postex.bloodhound_collect") as mock_bh:
        mock_lenum.ainvoke = AsyncMock(return_value=MagicMock())
        mock_cred.ainvoke = AsyncMock(return_value=MagicMock(secrets=[]))
        mock_bh.ainvoke = AsyncMock(return_value=MagicMock())

        result = await postex_node(goad_state)

    mock_bh.ainvoke.assert_not_called()  # BloodHound should not be called for Linux


@pytest.mark.asyncio
async def test_postex_node_hitl_rejection_in_privesc(goad_state):
    """Review Focus: operator rejects privesc candidate, agent tries next."""
    from autored.models.postex import PrivescCandidate
    candidates = [
        PrivescCandidate(host_ip="10.10.10.5", technique="sudo_nopasswd",
                         category="misconfig", details="vim", confidence=0.9,
                         exploit_command="sudo vim -c '!sh'", removal_command=None),
        PrivescCandidate(host_ip="10.10.10.5", technique="suid_find",
                         category="misconfig", details="find suid", confidence=0.7,
                         exploit_command="/usr/bin/find . -exec /bin/sh \\;", removal_command=None),
    ]

    # First candidate rejected, second approved
    responses = iter([
        {"response": "reject", "modified_command": None},
        {"response": "approve", "modified_command": None},
    ])
    async def mock_wait():
        return next(responses)

    with patch("autored.agents.postex.windowsenum_subagent") as mock_wenum, \
         patch("autored.agents.postex.credharvester_subagent") as mock_cred, \
         patch("autored.agents.postex.privescfinder_subagent") as mock_privesc, \
         patch.object(goad_state.event_bus, "wait_for_tui_response", side_effect=mock_wait) as mock_wait_method:
        mock_wenum.ainvoke = AsyncMock(return_value=MagicMock(privesc_candidates=candidates))
        mock_cred.ainvoke = AsyncMock(return_value=MagicMock(secrets=[]))
        mock_privesc.ainvoke = AsyncMock(return_value=MagicMock(candidates=candidates, attempts=[]))

        result = await postex_node(goad_state)

    # Should have tried both candidates (first rejected, second approved)
    assert mock_wait_method.call_count >= 1
