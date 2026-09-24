"""Phase 3, Task 15 — E2E test against HackTheBox Blue (10.10.10.40).

This module is **skipped by default**. Set ``AUTORED_E2E=1`` to opt in.

When enabled, the test runs the real Phase 3 graph (real LLM via the
model router, real subprocess calls to ``nmap`` / ``naabu`` / ``httpx``
/ ``nuclei`` / ``feroxbuster`` / ``subfinder`` / ``amass`` / ``dnsx``
/ ``gobuster`` / ``searchsploit``, real NVD HTTP, real Metasploit RPC
via ``msfrpcd``) against the live HTB Blue target.

Blue is the canonical EternalBlue (MS17-010) box — an unpatched Windows
7 / Server 2008 R2 SMB service exploitable via the Metasploit module
``exploit/windows/smb/ms17_010_eternalblue``. The Phase 3 test verifies
the full kill chain (recon → vuln → exploit) reaches a verified foothold.

Prerequisites
-------------
- HackTheBox VPN connected (``sudo openvpn user.ovpn``).
- ``ANTHROPIC_API_KEY`` (Sonnet 4.5 powers ``plan_recon`` +
  ``synthesize_findings`` + ``plan_exploit``) and ``DEEPSEEK_API_KEY``
  (powers ``second_opinion`` critique) set in the environment.
- All 10 CLI tools installed and on ``PATH``: ``nmap``, ``naabu``,
  ``httpx``, ``nuclei``, ``feroxbuster``, ``subfinder``, ``amass``,
  ``dnsx``, ``gobuster``, ``searchsploit``.
- **Metasploit RPC daemon running** on localhost:55553::

      msfrpcd -P msf -p 55553 -a 127.0.0.1

  (The msfagent sub-agent connects to this daemon to launch the
  ``ms17_010_eternalblue`` module against the target.)
- A reachable reverse-handler port on the operator's HTB VPN IP
  (default LHOST in the LLM-generated plan — set the IP before running
  the test so the meterpreter reverse_tcp payload can dial back).
- ``AUTORED_E2E=1`` env var.

Run
---
    AUTORED_E2E=1 uv run pytest tests/e2e/test_phase3_blue.py -v -s

Expected runtime: 15-20 minutes against HTB Blue. The test passes if:

- Recon discovers port 445 (SMB — Microsoft Windows 7 or similar).
- The Vuln Agent produces at least 1 attack hypothesis.
- At least one hypothesis references EternalBlue / MS17-010 / CVE-2017-0144
  via ``h.cve`` or ``h.technique``.
- The Exploit Agent records at least 1 verified ``Foothold`` whose
  ``method`` field contains the EternalBlue technique string.
- The Phase 3 graph terminates with ``state.phase == "done"`` (the
  report stub ran after the exploit node).

Mirrors the Phase 2 Shocker E2E test (T13) in structure; differs in
target (Blue vs Shocker) and in the exploit verification (foothold
recorded vs hypotheses produced).
"""
import os

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("AUTORED_E2E") != "1",
    reason="E2E test requires AUTORED_E2E=1 + live HTB VPN + API keys + msfrpcd",
)


@pytest.mark.asyncio
async def test_phase3_blue_eternalblue(tmp_path, monkeypatch):
    """E2E: run full Phase 3 (recon + vuln + exploit) against HTB Blue.

    Targets ``10.10.10.40`` (HTB Blue) — the canonical EternalBlue
    (MS17-010) box. The test exercises the full Phase 3 graph: recon
    discovers SMB on port 445, the Vuln Agent produces an
    EternalBlue hypothesis, the Exploit Agent runs the
    ``exploit/windows/smb/ms17_010_eternalblue`` Metasploit module via
    msfrpcd, and the verified foothold is recorded in state.

    Requires:
    - HackTheBox VPN connected
    - ANTHROPIC_API_KEY and DEEPSEEK_API_KEY set
    - nmap, naabu, httpx, nuclei, feroxbuster, subfinder, amass, dnsx,
      gobuster, searchsploit installed and on PATH
    - msfrpcd running on 127.0.0.1:55553 with password 'msf'
    - A reachable reverse-handler port on the operator's HTB VPN IP
    - AUTORED_E2E=1 env var
    """
    # Imports kept inside the test so a missing dependency at module
    # load doesn't poison collection when AUTORED_E2E is unset.
    from autored.config import RulesOfEngagement
    from autored.graph import build_phase3_graph
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

    # Sandbox RoE (allows 0.0.0.0/0) — never run E2E against production.
    # auto_approve: the operator isn't sitting at the TUI to approve
    # each hypothesis; the gate short-circuits so the run completes
    # unattended. (For an interactive E2E with HitL gates, set
    # hitl_mode="always_ask" and run with --tui.)
    roe = RulesOfEngagement(
        engagement_name="E2E Blue Test",
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

    engagement_id = generate_engagement_id("10.10.10.40", "e2e-blue")
    register_roe(engagement_id, roe)
    init_engagement_folder(engagement_id, "10.10.10.40", "e2e-test")

    state = EngagementState(
        engagement_id=engagement_id,
        target_scope=["10.10.10.40"],
        operator="e2e-test",
        rules_of_engagement=roe,
    )

    checkpointer = await make_checkpointer(engagement_id)
    graph = build_phase3_graph(checkpointer)
    config = {"configurable": {"thread_id": engagement_id}}

    # Run with real LLM + real tools + real Metasploit RPC. Completes
    # in 15-20 minutes against HTB Blue (recon ~5min, vuln ~5min,
    # exploit ~5-10min including msfrpcd exploit dispatch + payload
    # delivery + meterpreter callback).
    try:
        final_state = await graph.ainvoke(state, config=config)
    finally:
        if hasattr(checkpointer, "conn"):
            await checkpointer.conn.close()

    # --- Assertions ----------------------------------------------------

    # Phase 3 ends at report_phase1 → phase='done'. (Phase 4 will route
    # exploit success → postex → ... → report; Phase 3 is linear.)
    assert final_state["phase"] == "done", f"Unexpected phase: {final_state['phase']}"
    assert len(final_state["hosts"]) >= 1, "No hosts discovered"

    # Blue should be present in the hosts list.
    assert any(
        h.ip == "10.10.10.40" for h in final_state["hosts"]
    ), "Blue host (10.10.10.40) not in hosts"

    # SMB (port 445) is the canonical EternalBlue surface on Blue.
    services = final_state["services"]
    ports = {s.port for s in services}
    assert 445 in ports, f"SMB (445) not discovered; ports={ports}"

    # Vuln Agent should have produced at least one hypothesis.
    hypotheses = final_state["attack_hypotheses"]
    assert len(hypotheses) >= 1, "Vuln Agent produced no attack hypotheses"

    # At least one hypothesis should reference EternalBlue / MS17-010 /
    # CVE-2017-0144 (the canonical Blue exploit).
    eternalblue_hypotheses = [
        h
        for h in hypotheses
        if (h.cve and "2017-0144" in h.cve)
        or "eternalblue" in (h.technique or "").lower()
        or "ms17-010" in (h.technique or "").lower()
        or "ms17_010" in (h.technique or "").lower()
    ]
    assert len(eternalblue_hypotheses) >= 1, (
        f"No EternalBlue/MS17-010 hypothesis found. Hypotheses: "
        f"{[(h.technique, h.cve) for h in hypotheses]}"
    )

    # Phase 3 assertion: Exploit Agent recorded a verified Foothold.
    footholds = final_state["footholds"]
    assert len(footholds) >= 1, "Exploit Agent recorded no foothold"

    # The foothold's `method` field mirrors `hypothesis.technique` (set
    # in `_build_foothold`). For a successful EternalBlue run, it
    # should contain "EternalBlue" or "MS17-010" / "ms17_010".
    method = footholds[0].method or ""
    assert (
        "eternalblue" in method.lower()
        or "ms17-010" in method.lower()
        or "ms17_010" in method.lower()
    ), f"foothold.method={method!r} does not reference EternalBlue/MS17-010"

    # Save state for inspection
    save_state_to_disk(engagement_id, EngagementState.model_validate(final_state))

    # Print findings for manual review (-s to see stdout)
    print(f"\nE2E Test Complete: {engagement_id}")
    print(f"Hosts: {len(final_state['hosts'])}")
    print(f"Services: {len(services)}")
    print(f"Vulnerabilities: {len(final_state['vulnerabilities'])}")
    print(f"Attack hypotheses: {len(hypotheses)}")
    print(f"Footholds: {len(footholds)}")
    for h in hypotheses[:3]:
        print(
            f"  #{h.rank}: {h.technique} (CVE: {h.cve}, "
            f"confidence: {h.confidence:.0%})"
        )
    for f in footholds:
        print(
            f"  Foothold: {f.host_ip} via {f.method} "
            f"(rank={f.hypothesis_rank}, access={f.access_type})"
        )
