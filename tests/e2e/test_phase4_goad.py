"""Phase 4, Task 15 — E2E test against GoAD (Game Of Active Directory).

This module is **skipped by default**. Set ``AUTORED_E2E=1`` to opt in.

When enabled, the test runs the real Phase 4 graph (real LLM via the
model router, real subprocess calls to ``nmap`` / ``naabu`` / ``httpx``
/ ``nuclei`` / ``feroxbuster`` / ``subfinder`` / ``amass`` / ``dnsx``
/ ``gobuster`` / ``searchsploit``, real NVD HTTP, real Metasploit RPC
via ``msfrpcd``, real BloodHound collection via ``bloodhound-python``,
real ``impacket`` ``secretsdump`` and ``mimikatz`` via the foothold
session manager) against a self-hosted GoAD lab.

GoAD (Game Of Active Directory) is a multi-VM Active Directory lab
designed for red-team training. The Phase 4 E2E test verifies the
Post-Ex Agent chain — foothold → enumeration → cred harvest →
privesc → persistence — completes against a real AD environment
with multiple nested trusts, Kerberos, and Windows-only defensive
mechanisms.

The canonical GoAD foothold is a Windows host (e.g., a member server
or workstation) reached via an initial exploit (e.g., EternalBlue,
MS17-010 on an unpatched Windows 7 box, or a credential-based foothold
via bruteagent). The Phase 4 test exercises the full post-ex chain on
that foothold: WindowsEnum surfaces local users + privesc candidates,
CredHarvester runs mimikatz to dump NTLM hashes + plaintext passwords,
BloodHound maps the AD trust graph, and the persistence + evasion +
exfiltration sub-agents install reversible persistence implants.

Prerequisites
-------------
- **GoAD lab deployed and running** locally (typically VirtualBox +
  Vagrant). See https://github.com/Orange-Cyberdefense/GOAD for
  setup. The default GoAD subnet is ``192.168.56.0/24``; the DC is
  typically ``192.168.56.10`` and the member servers ``.11/.12/.13``.
- **HackTheBox VPN NOT required** (GoAD is self-hosted). The operator
  must instead be on the GoAD host-only network
  (``ping 192.168.56.10`` succeeds from the operator's host).
- ``ANTHROPIC_API_KEY`` (Sonnet 4.5 powers ``plan_recon`` +
  ``synthesize_findings`` + ``plan_exploit``) and ``DEEPSEEK_API_KEY``
  (powers ``second_opinion`` critique) set in the environment.
- All 10 CLI tools installed and on ``PATH``: ``nmap``, ``naabu``,
  ``httpx``, ``nuclei``, ``feroxbuster``, ``subfinder``, ``amass``,
  ``dnsx``, ``gobuster``, ``searchsploit``.
- **Metasploit RPC daemon running** on ``127.0.0.1:55553`` with
  password ``msf``::

      msfrpcd -P msf -p 55553 -a 127.0.0.1

  (The msfagent sub-agent dispatches the initial foothold exploit via
  this daemon.)
- **``impacket``** installed (``pip install impacket``) — powers the
  ``secretsdump.py`` remote-hash-dump used by CredHarvester against
  Windows targets with credentials.
- **``bloodhound-python``** installed
  (``pip install bloodhound-python``) — powers the BloodHound data
  collector that maps the AD trust graph from harvested credentials.
- **Neo4j running** for BloodHound ingestion (the Phase 4
  ``bloodhound_collect`` tool ingests the JSON via Neo4j). See
  ``docker-compose neo4j up -d`` from the AutoRed repo root.
- **A reachable reverse-handler port** on the operator's GoAD network
  IP (default LHOST in the LLM-generated plan — the meterpreter
  ``reverse_tcp`` payload dials back to this address).
- ``AUTORED_E2E=1`` env var.

Run
---
    AUTORED_E2E=1 uv run pytest tests/e2e/test_phase4_goad.py -v -s

Expected runtime: 30-60 minutes against GoAD (recon ~5min, vuln ~5min,
exploit ~5-10min for the initial foothold, then post-ex ~15-30min
covering WindowsEnum + mimikatz + BloodHound + persistence + evasion +
exfil on the foothold). The test passes if all of the following hold:

- Recon discovers at least one Windows host on the GoAD subnet.
- The Vuln Agent produces at least 1 attack hypothesis.
- The Exploit Agent records at least 1 verified ``Foothold`` with
  ``access_type`` indicating a Windows session (``winrm`` / ``shell``
  with ``method`` referencing a Windows exploit like MS17-010 or a
  credential-based foothold).
- The Post-Ex Agent records at least 1 ``local_users`` entry (WindowsEnum
  surfaced local accounts).
- The Post-Ex Agent records at least 1 ``harvested_secrets`` entry
  (mimikatz dumped NTLM hashes or plaintext passwords).
- The Post-Ex Agent records at least 1 ``persistence_artifacts`` entry
  (persistence is permitted by the sandbox RoE + auto-approve
  short-circuits the HitL gate — a scheduled_task or registry Run key
  implant is established on the foothold).
- The Phase 4 graph terminates with ``state.phase == "done"`` (the
  report stub ran after the postex node).

Mirrors the Phase 3 Blue E2E test (T15) in structure; differs in
target (GoAD vs HTB Blue) and in the post-ex chain assertions (Phase 3
stops at the foothold; Phase 4 extends through post-ex).
"""
import os

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("AUTORED_E2E") != "1",
    reason=(
        "E2E test requires AUTORED_E2E=1 + live GoAD lab + API keys "
        "+ msfrpcd + impacket + bloodhound-python + Neo4j"
    ),
)


@pytest.mark.asyncio
async def test_phase4_goad_postex_chain(tmp_path, monkeypatch):
    """E2E: run full Phase 4 (recon + vuln + exploit + postex) against GoAD.

    Targets ``192.168.56.10`` (canonical GoAD DC entry point — the
    operator may override via ``AUTORED_GOAD_TARGET``). The test
    exercises the full Phase 4 graph: recon discovers Windows hosts,
    the Vuln Agent produces an exploit hypothesis, the Exploit Agent
    establishes a Windows foothold, and the Post-Ex Agent runs the
    six sub-activities per foothold (enumeration → BloodHound →
    privesc → persistence → evasion → exfiltration).

    Requires:
    - GoAD lab deployed and reachable (``ping 192.168.56.10``).
    - ANTHROPIC_API_KEY and DEEPSEEK_API_KEY set.
    - nmap, naabu, httpx, nuclei, feroxbuster, subfinder, amass, dnsx,
      gobuster, searchsploit installed and on PATH.
    - msfrpcd running on 127.0.0.1:55553 with password 'msf'.
    - impacket + bloodhound-python installed.
    - Neo4j running for BloodHound ingestion.
    - A reachable reverse-handler port on the operator's GoAD IP.
    - AUTORED_E2E=1 env var.
    """
    # Imports kept inside the test so a missing dependency at module
    # load doesn't poison collection when AUTORED_E2E is unset.
    from autored.config import RulesOfEngagement
    from autored.graph import build_phase4_graph
    from autored.logging import setup_logging
    from autored.persistence.filesystem import (
        init_engagement_folder,
        save_state_to_disk,
    )
    from autored.persistence.sqlite_saver import make_checkpointer
    from autored.roe_guard import register_roe
    from autored.state import EngagementState
    from autored.utils import generate_engagement_id

    monkeypatch.chdir(tmp_path)
    setup_logging(log_dir=str(tmp_path / "logs"))

    # Canonical GoAD DC entry point — operator can override via env
    # for non-default GoAD deployments.
    target = os.environ.get("AUTORED_GOAD_TARGET", "192.168.56.10")

    # Sandbox RoE (allows 0.0.0.0/0 + persistence + evasion + exfil +
    # kernel) — never run E2E against production.
    # auto_approve: the operator isn't sitting at the TUI to approve
    # each privesc candidate / persistence / evasion / exfil gate; the
    # gates short-circuit so the run completes unattended. (For an
    # interactive E2E with HitL gates, set hitl_mode="always_ask" and
    # run with --tui.)
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

    engagement_id = generate_engagement_id(target, "e2e-goad-phase4")
    register_roe(engagement_id, roe)
    init_engagement_folder(engagement_id, target, "e2e-test")

    state = EngagementState(
        engagement_id=engagement_id,
        target_scope=[target],
        operator="e2e-test",
        rules_of_engagement=roe,
    )

    checkpointer = await make_checkpointer(engagement_id)
    graph = build_phase4_graph(checkpointer)
    config = {"configurable": {"thread_id": engagement_id}}

    # Run with real LLM + real tools + real Metasploit RPC + real
    # impacket + real bloodhound-python. Completes in 30-60 minutes
    # against GoAD (recon ~5min, vuln ~5min, exploit ~5-10min, post-ex
    # ~15-30min including WindowsEnum + mimikatz + BloodHound +
    # persistence + evasion + exfil on the foothold).
    try:
        final_state = await graph.ainvoke(state, config=config)
    finally:
        if hasattr(checkpointer, "conn"):
            await checkpointer.conn.close()

    # --- Assertions ----------------------------------------------------

    # Phase 4 ends at report_phase1 → phase='done' (the report stub
    # overwrites postex's phase='lateral').
    assert final_state["phase"] == "done", (
        f"Unexpected phase: {final_state['phase']}"
    )
    assert len(final_state["hosts"]) >= 1, "No hosts discovered"

    # At least one Windows host should be in the hosts list (GoAD is
    # an all-Windows AD lab).
    assert any(
        h.ip == target for h in final_state["hosts"]
    ), f"GoAD target ({target}) not in hosts"

    # Vuln Agent should have produced at least one hypothesis.
    hypotheses = final_state["attack_hypotheses"]
    assert len(hypotheses) >= 1, "Vuln Agent produced no attack hypotheses"

    # Exploit Agent should have recorded at least 1 verified foothold.
    footholds = final_state["footholds"]
    assert len(footholds) >= 1, "Exploit Agent recorded no foothold"

    # --- Phase 4 post-ex assertions ----------------------------------
    # The full post-ex chain on the foothold should have produced:
    # local_users (WindowsEnum surfaced local accounts).
    local_users = final_state["local_users"]
    assert len(local_users) >= 1, (
        "Post-Ex Agent recorded no local_users (WindowsEnum should "
        "have surfaced >=1 local account on a Windows foothold)"
    )

    # harvested_secrets (mimikatz dumped NTLM hashes / plaintext).
    harvested_secrets = final_state["harvested_secrets"]
    assert len(harvested_secrets) >= 1, (
        "Post-Ex Agent recorded no harvested_secrets (mimikatz should "
        "have dumped >=1 NTLM hash or plaintext password on the "
        "Windows foothold)"
    )

    # persistence_artifacts (persistence_allowed + auto_approve →
    # a scheduled_task / registry Run key / etc. implant).
    persistence_artifacts = final_state["persistence_artifacts"]
    assert len(persistence_artifacts) >= 1, (
        "Post-Ex Agent recorded no persistence_artifacts "
        "(persistenceagent_subagent should have installed >=1 "
        "reversible implant)"
    )
    # RF#3: every persistence artifact MUST carry a removal_command
    # (Phase 5 Cleanup Agent walks the list and runs them verbatim).
    for art in persistence_artifacts:
        assert art.removal_command, (
            f"PersistenceArtifact {art.id} ({art.method}) has empty "
            "removal_command — Phase 5 Cleanup cannot reverse it"
        )

    # Save state for inspection
    save_state_to_disk(
        engagement_id, EngagementState.model_validate(final_state)
    )

    # Print findings for manual review (-s to see stdout)
    print(f"\nE2E Test Complete: {engagement_id}")
    print(f"Hosts: {len(final_state['hosts'])}")
    print(f"Services: {len(final_state['services'])}")
    print(f"Vulnerabilities: {len(final_state['vulnerabilities'])}")
    print(f"Attack hypotheses: {len(hypotheses)}")
    print(f"Footholds: {len(footholds)}")
    print(f"Local users: {len(local_users)}")
    print(f"Harvested secrets: {len(harvested_secrets)}")
    print(f"Privesc candidates: {len(final_state['privesc_candidates'])}")
    print(f"Privesc attempts: {len(final_state['privesc_attempts'])}")
    print(f"Persistence artifacts: {len(persistence_artifacts)}")
    print(f"Evasion actions: {len(final_state['evasion_actions'])}")
    print(f"Exfil proofs: {len(final_state['exfiltration_proof'])}")
    for f in footholds[:3]:
        print(
            f"  Foothold: {f.host_ip} via {f.method} "
            f"(rank={f.hypothesis_rank}, access={f.access_type})"
        )
    for art in persistence_artifacts[:3]:
        print(
            f"  Persistence: {art.method} on {art.host_ip} "
            f"(removal: {art.removal_command[:60]}...)"
        )
