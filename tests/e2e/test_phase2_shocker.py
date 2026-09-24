"""Phase 2, Task 13 — E2E test against HackTheBox Shocker (10.10.10.56).

This module is **skipped by default**. Set ``AUTORED_E2E=1`` to opt in.

When enabled, the test runs the real Phase 2 graph (real LLM via the
model router, real subprocess calls to ``nmap`` / ``naabu`` / ``httpx``
/ ``nuclei`` / ``feroxbuster`` / ``subfinder`` / ``amass`` / ``dnsx``
/ ``gobuster`` / ``searchsploit``, real NVD HTTP) against the live HTB
Shocker target.

Prerequisites
-------------
- HackTheBox VPN connected (``sudo openvpn user.ovpn``).
- ``ANTHROPIC_API_KEY`` (Sonnet 4.5 powers ``plan_recon`` +
  ``synthesize_findings``) and ``DEEPSEEK_API_KEY`` (powers
  ``second_opinion`` critique) set in the environment.
- All 10 CLI tools installed and on ``PATH``: ``nmap``, ``naabu``,
  ``httpx``, ``nuclei``, ``feroxbuster``, ``subfinder``, ``amass``,
  ``dnsx``, ``gobuster``, ``searchsploit``.
- ``AUTORED_E2E=1`` env var.

Run
---
    AUTORED_E2E=1 uv run pytest tests/e2e/test_phase2_shocker.py -v -s

Expected runtime: 10-15 minutes against HTB Shocker. The test passes if:

- Recon discovers port 80 (Apache httpd 2.2.22) — the canonical Shocker
  surface (Shellshock is exploitable via ``/cgi-bin/``).
- The Vuln Agent produces at least 1 attack hypothesis.
- At least one hypothesis references Shellshock (``CVE-2014-6271``)
  either via ``h.cve`` or via ``h.technique``.

Mirrors the Phase 1 Lame E2E test (T29) in structure; differs in target +
assertions (Phase 2 ends at the report stub, not the recon boundary).
"""

import os

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("AUTORED_E2E") != "1",
    reason="E2E test requires AUTORED_E2E=1 + live HTB VPN + API keys",
)


@pytest.mark.asyncio
async def test_phase2_shocker_recon_vuln(tmp_path, monkeypatch):
    """E2E: run full Phase 2 (recon + vuln) against HTB Shocker (10.10.10.56).

    Requires:
    - HackTheBox VPN connected
    - ANTHROPIC_API_KEY and DEEPSEEK_API_KEY set
    - nmap, naabu, httpx, nuclei, feroxbuster, subfinder, amass, dnsx,
      gobuster, searchsploit installed and on PATH
    - AUTORED_E2E=1 env var
    """
    # Imports kept inside the test so a missing dependency at module
    # load doesn't poison collection when AUTORED_E2E is unset.
    from autored.config import RulesOfEngagement
    from autored.graph import build_phase2_graph
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
    roe = RulesOfEngagement(
        engagement_name="E2E Shocker Test",
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

    engagement_id = generate_engagement_id("10.10.10.56", "e2e-shocker")
    register_roe(engagement_id, roe)
    init_engagement_folder(engagement_id, "10.10.10.56", "e2e-test")

    state = EngagementState(
        engagement_id=engagement_id,
        target_scope=["10.10.10.56"],
        operator="e2e-test",
        rules_of_engagement=roe,
    )

    checkpointer = await make_checkpointer(engagement_id)
    graph = build_phase2_graph(checkpointer)
    config = {"configurable": {"thread_id": engagement_id}}

    # Run with real LLM and real tools — completes in under 10-15 min.
    try:
        final_state = await graph.ainvoke(state, config=config)
    finally:
        if hasattr(checkpointer, "conn"):
            await checkpointer.conn.close()

    # Assertions
    assert final_state["phase"] in ("done", "exploit"), f"Unexpected phase: {final_state['phase']}"
    assert len(final_state["hosts"]) >= 1, "No hosts discovered"
    assert any(
        h.ip == "10.10.10.56" for h in final_state["hosts"]
    ), "Shocker host (10.10.10.56) not in hosts"

    # Shocker should have port 80 open (Apache httpd 2.2.22 — Shellshock surface).
    services = final_state["services"]
    ports = {s.port for s in services}
    assert 80 in ports, f"Port 80 not found in services: {ports}"

    # Vuln Agent should have produced hypotheses
    hypotheses = final_state["attack_hypotheses"]
    assert len(hypotheses) >= 1, "Vuln Agent produced no attack hypotheses"

    # At least one hypothesis should reference Shellshock or CVE-2014-6271.
    shocker_hypotheses = [
        h
        for h in hypotheses
        if (h.cve and "2014-6271" in h.cve) or "shellshock" in (h.technique or "").lower()
    ]
    assert len(shocker_hypotheses) >= 1, (
        f"No Shellshock hypothesis found. Hypotheses: "
        f"{[(h.technique, h.cve) for h in hypotheses]}"
    )

    # Save state for inspection
    save_state_to_disk(engagement_id, EngagementState.model_validate(final_state))

    # Print findings for manual review (-s to see stdout)
    print(f"\nE2E Test Complete: {engagement_id}")
    print(f"Hosts: {len(final_state['hosts'])}")
    print(f"Services: {len(services)}")
    print(f"Vulnerabilities: {len(final_state['vulnerabilities'])}")
    print(f"Attack hypotheses: {len(hypotheses)}")
    for h in hypotheses[:3]:
        print(f"  #{h.rank}: {h.technique} (CVE: {h.cve}, " f"confidence: {h.confidence:.0%})")
