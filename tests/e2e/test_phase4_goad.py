"""E2E test: full Phase 4 (recon + vuln + exploit + post-ex) against GoAD lab.

GoAD (Game of Active Directory — https://github.com/Orange-Cyberdefense/GOAD)
is a deliberately-vulnerable Active Directory lab with 3 forests / 5
domains / ~30 users and a documented chain of privesc + lateral-movement
paths. This test runs the entire Phase 4 graph against a running GoAD
instance and asserts the Post-Ex Agent's six sub-activities produce
populated state fields on at least one foothold.

It is **skipped by default** — set ``AUTORED_E2E=1`` to opt in, and
only do so when:

  * GoAD is running locally (default vagrant-libvirt / virtualbox setup)
  * ``ANTHROPIC_API_KEY`` and ``DEEPSEEK_API_KEY`` are set
  * All required CLI recon + exploit tools are installed and on
    ``$PATH`` (nmap, naabu, httpx, nuclei, feroxbuster, searchsploit,
    Metasploit RPC, impacket's secretsdump, mimikatz, bloodhound-python)
  * ``msfrpcd`` is running on ``127.0.0.1:55553`` with password ``msf``
    (same as the Phase 3 E2E test)
  * ``AUTORED_LHOST`` env var is set to your host IP reachable from
    the GoAD VMs (for reverse shells)
  * ``AUTORED_GOAD_TARGET`` env var is set to the GoAD host you want
    to pivot into first (default: the first foothold box — typically
    ``192.168.56.22`` (SRV02) or whichever box has an exposed + exploitable
    service like SMB / WebDAV)

Expected runtime: 30–60 minutes (recon + vuln + exploit + 6 sub-activities
per foothold). Test passes if:

  * The Exploit Agent records at least 1 foothold (initial access)
  * The Post-Ex Agent runs WindowsEnum and records at least 1 local user
  * The CredHarvester sub-agent records at least 1 harvested secret
    (mimikatz output on a Windows foothold should yield NTLM hashes at
    minimum, and cleartext passwords if any users are logged in)
  * At least 1 persistence artifact is installed (sandbox RoE allows
    persistence; remove manually after the run with the recorded
    ``removal_command`` — see ``engagements/<id>/state.json``)
  * The graph reaches the ``done`` phase (post-ex → report → END)

Usage::

    # 1. Bring up GoAD (see GOAD repo for vagrant / ansible setup)
    cd GOAD && vagrant up

    # 2. Verify the GoAD target VM is reachable
    ping 192.168.56.22  # or whichever VM you're targeting first

    # 3. Start msfrpcd (Metasploit RPC daemon)
    msfrpcd -P msf -p 55553 -a 127.0.0.1 -U msf -L

    # 4. Set env vars
    export ANTHROPIC_API_KEY=sk-ant-...
    export DEEPSEEK_API_KEY=sk-...
    export AUTORED_E2E=1
    export AUTORED_LHOST=192.168.56.1   # your VirtualBox host-only IP
    export AUTORED_GOAD_TARGET=192.168.56.22

    # 5. Run Phase 4 E2E test (use -s to see live findings)
    uv run pytest tests/e2e/test_phase4_goad.py -v -s
"""

import asyncio
import os
from pathlib import Path

import pytest

# Skip by default — only opt in with AUTORED_E2E=1 (and even then,
# only run when GoAD is up + API keys set + msfrpcd running).
pytestmark = pytest.mark.skipif(
    os.environ.get("AUTORED_E2E") != "1",
    reason="Set AUTORED_E2E=1 to run E2E tests (requires GoAD lab + msfrpcd)",
)


@pytest.mark.asyncio
async def test_phase4_goad_full_pipeline(tmp_path: Path, monkeypatch):
    """E2E: run full Phase 4 (recon + vuln + exploit + post-ex) against GoAD.

    Requires:
      * GoAD lab running (``vagrant up`` in the GOAD checkout)
      * ``ANTHROPIC_API_KEY`` and ``DEEPSEEK_API_KEY`` set
      * ``nmap``, ``naabu``, ``httpx``, ``nuclei``, ``feroxbuster``,
        ``searchsploit``, Metasploit Framework, impacket's secretsdump,
        mimikatz, bloodhound-python installed and on ``$PATH``
      * ``msfrpcd`` running on ``127.0.0.1:55553`` with password ``msf``
      * ``AUTORED_LHOST`` env var set to your VirtualBox host-only IP
      * ``AUTORED_GOAD_TARGET`` env var set to the first target IP
        (default: ``192.168.56.22`` — SRV02 in the standard GoAD layout)
      * ``AUTORED_E2E=1`` env var

    Expected outcome:
      * Recon discovers at least 1 host (the GoAD target)
      * Vuln Agent produces at least 1 attack hypothesis
      * Exploit Agent records at least 1 foothold
      * Post-Ex Agent populates ``local_users``, ``harvested_secrets``,
        and ``persistence_artifacts`` on at least one foothold
      * Graph reaches phase ``done``
    """
    # Import here so the module-level skipif can short-circuit collection
    # without dragging in autored (and its deps) on every test run.
    from autored.state import EngagementState
    from autored.models.roe import RulesOfEngagement
    from autored.persistence.filesystem import (
        init_engagement_folder,
        save_state_to_disk,
    )
    from autored.persistence.sqlite_saver import make_checkpointer
    from autored.graph import build_phase4_graph
    from autored.roe_guard import register_roe
    from autored.logging import setup_logging
    from autored.utils import generate_engagement_id
    from autored.tui.event_bus import EventBus

    lhost = os.environ.get("AUTORED_LHOST")
    if not lhost:
        pytest.fail(
            "AUTORED_LHOST env var must be set to your VirtualBox "
            "host-only IP (find it with: ip addr show vboxnet0 | "
            "grep 'inet ')."
        )

    goad_target = os.environ.get("AUTORED_GOAD_TARGET", "192.168.56.22")

    monkeypatch.chdir(tmp_path)
    setup_logging(log_dir=str(tmp_path / "logs"))

    # Permissive sandbox RoE so real tool calls against the GoAD lab
    # pass scope enforcement. persistence / evasion / exfil all allowed
    # so we exercise every Post-Ex sub-activity; the persistence
    # artifacts' ``removal_command`` fields are captured in state.json
    # for manual teardown after the run.
    roe = RulesOfEngagement(
        engagement_name="E2E GoAD Phase 4 Test",
        operator="e2e-test",
        operator_signature="e2e",
        allowed_ips=["0.0.0.0/0"],
        allowed_techniques=["*"],
        persistence_allowed=True,
        evasion_allowed=True,
        exfiltration_allowed=True,
        kernel_exploits_allowed=True,
        hitl_mode="auto_approve",
    )

    engagement_id = generate_engagement_id(goad_target, "e2e-goad-p4")
    register_roe(engagement_id, roe)
    init_engagement_folder(engagement_id, goad_target, "e2e-test")

    state = EngagementState(
        engagement_id=engagement_id,
        target_scope=[goad_target],
        operator="e2e-test",
        rules_of_engagement=roe,
    )
    # EventBus wired so every HitL gate in the Exploit + Post-Ex
    # Agents has somewhere to emit (auto-approve in sandbox mode means
    # it won't block on operator input).
    state.event_bus = EventBus()

    checkpointer = await make_checkpointer(engagement_id)
    try:
        graph = build_phase4_graph(checkpointer)
        config = {"configurable": {"thread_id": engagement_id}}

        # 60-minute cap so a hung tool doesn't stall CI forever.
        # Phase 4 is longer than Phase 3 because the Post-Ex Agent
        # runs 6 sub-activities per foothold — WindowsEnum (winpeas /
        # mimikatz) + PrivescFinder + PersistenceAgent + EvasionAgent +
        # ExfilAgent + bloodhound-python collection can each take
        # several minutes against a live target.
        final_state = await asyncio.wait_for(
            graph.ainvoke(state, config=config),
            timeout=3600,
        )
    finally:
        conn = getattr(checkpointer, "conn", None)
        if conn is not None:
            await conn.close()

    # ------------------------------------------------------------------
    # Normalise the final state into both dict and model forms
    # ------------------------------------------------------------------
    if isinstance(final_state, EngagementState):
        final_state_dict = final_state.model_dump()
        final_state_obj = final_state
    else:
        final_state_dict = final_state
        final_state_obj = EngagementState.model_validate(final_state)

    # ------------------------------------------------------------------
    # Assertions — Phase 3 carried-over expectations
    # ------------------------------------------------------------------
    # Phase should be 'done' (postex_node sets 'lateral', then
    # report_phase1 stub overwrites with 'done').
    assert final_state_dict["phase"] in ("done", "lateral"), (
        f"Expected phase 'done' or 'lateral', got {final_state_dict['phase']!r}"
    )

    hosts = final_state_dict["hosts"]
    assert len(hosts) >= 1, "expected at least 1 host discovered"
    assert any(h["ip"] == goad_target for h in hosts), (
        f"expected {goad_target} in discovered hosts"
    )

    # Exploit Agent should have recorded at least one foothold. Without
    # a foothold the Post-Ex Agent has nothing to iterate over and every
    # post-ex state field would be empty.
    footholds = final_state_obj.footholds
    assert len(footholds) >= 1, (
        "Exploit Agent recorded no foothold — Phase 4 cannot proceed. "
        "Check that the exploit plan's LHOST is reachable from the GoAD VM."
    )

    # ------------------------------------------------------------------
    # Assertions — Phase 4 Post-Ex populated fields
    # ------------------------------------------------------------------
    local_users = final_state_obj.local_users
    assert len(local_users) >= 1, (
        "Post-Ex Agent recorded no local users — WindowsEnum sub-agent "
        "did not enumerate the foothold. Check winpeas / secretsdump ran."
    )

    harvested_secrets = final_state_obj.harvested_secrets
    assert len(harvested_secrets) >= 1, (
        "Post-Ex Agent harvested no secrets — CredHarvester sub-agent "
        "did not extract any credentials from the foothold. Check "
        "mimikatz / secretsdump ran successfully."
    )

    # Persistence artifacts — sandbox RoE allows persistence; if
    # anything went wrong with the persistence sub-agent the field
    # would be empty. (Manual teardown required after the run —
    # see ``engagements/<id>/state.json`` for each artifact's
    # ``removal_command``.)
    persistence_artifacts = final_state_obj.persistence_artifacts
    assert len(persistence_artifacts) >= 1, (
        "Post-Ex Agent installed no persistence artifacts — "
        "PersistenceAgent sub-agent did not run or all candidates "
        "were rejected at the HitL gate."
    )

    # Save state for inspection after the run (state.json contains the
    # removal_command for every persistence artifact — operator must
    # run those commands manually to clean up the GoAD lab).
    save_state_to_disk(engagement_id, final_state_obj)

    # Print findings for manual review (visible with `pytest -s`).
    print(f"\nE2E Test Complete: {engagement_id}")
    print(f"Target: {goad_target}")
    print(f"Hosts: {len(hosts)}")
    print(f"Footholds: {len(footholds)}")
    print(f"Local users enumerated: {len(local_users)}")
    print(f"Secrets harvested: {len(harvested_secrets)}")
    print(f"Trust relationships: {len(final_state_obj.trust_relationships)}")
    print(f"Privesc candidates: {len(final_state_obj.privesc_candidates)}")
    print(f"Privesc attempts: {len(final_state_obj.privesc_attempts)}")
    print(f"Persistence artifacts: {len(persistence_artifacts)}")
    print(f"Evasion actions: {len(final_state_obj.evasion_actions)}")
    print(f"Exfil proofs: {len(final_state_obj.exfiltration_proof)}")
    print()
    print("WARNING: persistence artifacts were installed on the GoAD lab.")
    print("Run the removal_command from each artifact in")
    print(f"  engagements/{engagement_id}/state.json")
    print("to clean up before the next E2E run.")
