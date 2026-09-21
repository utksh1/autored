"""E2E test: full Phase 2 (recon + vuln) against HackTheBox Shocker (10.10.10.56).

This test runs the entire Phase 2 graph against the real Shocker box on
HackTheBox, with the real LLMs (Claude Sonnet 4.5 for synthesis,
DeepSeek 3.2 for second opinion) and real tools (nmap, naabu, httpx,
nuclei, feroxbuster, subfinder, amass, dnsx, gobuster, searchsploit).
It is **skipped by default** — set ``AUTORED_E2E=1`` to opt in, and only
do so when:

  * You are connected to the HackTheBox VPN (``sudo openvpn user.ovpn``)
  * ``ANTHROPIC_API_KEY`` and ``DEEPSEEK_API_KEY`` are set
  * All required CLI tools are installed and on ``$PATH``

Expected runtime: 10–15 minutes. Test passes if:

  * nmap discovers port 80 (Apache httpd 2.2.22) on Shocker
  * The Vuln Agent produces at least one attack hypothesis
  * At least one hypothesis references Shellshock (CVE-2014-6271)

Usage::

    # 1. Connect to HackTheBox VPN
    sudo openvpn user.ovpn

    # 2. Verify target is reachable
    ping 10.10.10.56

    # 3. Set env vars
    export ANTHROPIC_API_KEY=sk-ant-...
    export DEEPSEEK_API_KEY=sk-...
    export AUTORED_E2E=1

    # 4. Run E2E test (use -s to see live findings + hypothesis printout)
    uv run pytest tests/e2e/test_phase2_shocker.py -v -s
"""

import asyncio
import os
from pathlib import Path

import pytest

# Skip by default — only opt in with AUTORED_E2E=1 (and even then,
# only run when connected to HTB VPN with API keys set).
pytestmark = pytest.mark.skipif(
    os.environ.get("AUTORED_E2E") != "1",
    reason="Set AUTORED_E2E=1 to run E2E tests (requires HTB VPN)",
)


@pytest.mark.asyncio
async def test_phase2_shocker_recon_vuln(tmp_path: Path, monkeypatch):
    """E2E: run full Phase 2 (recon + vuln) against HTB Shocker (10.10.10.56).

    Requires:
      * HackTheBox VPN connected
      * ``ANTHROPIC_API_KEY`` and ``DEEPSEEK_API_KEY`` set
      * ``nmap``, ``naabu``, ``httpx``, ``nuclei``, ``feroxbuster``,
        ``subfinder``, ``amass``, ``dnsx``, ``gobuster``, ``searchsploit``
        installed and on ``$PATH``
      * ``AUTORED_E2E=1`` env var

    Expected outcome:
      * Recon discovers port 80 (Apache httpd 2.2.22)
      * Vuln Agent identifies Shellshock (CVE-2014-6271) as a hypothesis
      * Attack hypotheses produced with Shellshock present
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
    from autored.graph import build_phase2_graph
    from autored.roe_guard import register_roe
    from autored.logging import setup_logging
    from autored.utils import generate_engagement_id

    monkeypatch.chdir(tmp_path)
    setup_logging(log_dir=str(tmp_path / "logs"))

    # Permissive sandbox RoE (0.0.0.0/0) so real tool calls against
    # 10.10.10.56 pass scope enforcement.
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
    try:
        graph = build_phase2_graph(checkpointer)
        config = {"configurable": {"thread_id": engagement_id}}

        # 15-minute cap so a hung tool doesn't stall CI forever.
        # Phase 2 is longer than Phase 1 because the Vuln Agent runs
        # CVE correlation + exploit search + self-critique (up to 3
        # Sonnet/DeepSeek round-trips).
        final_state = await asyncio.wait_for(
            graph.ainvoke(state, config=config),
            timeout=900,
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
    # Assertions
    # ------------------------------------------------------------------
    # Phase should be 'done' (graph reached report_phase1 stub after
    # vuln_node set phase='exploit'). 'exploit' is also acceptable in
    # case the report_phase1 stub changes in Phase 3.
    assert final_state_dict["phase"] in ("done", "exploit"), (
        f"Expected phase 'done' or 'exploit', got {final_state_dict['phase']!r}"
    )

    hosts = final_state_dict["hosts"]
    assert len(hosts) >= 1, "expected at least 1 host discovered"
    assert any(h["ip"] == "10.10.10.56" for h in hosts), (
        "expected 10.10.10.56 in discovered hosts"
    )

    # Shocker should have port 80 open (Apache httpd 2.2.22)
    services = final_state_dict["services"]
    ports = {s["port"] for s in services}
    assert 80 in ports, f"Port 80 not found in services: {sorted(ports)}"

    # Vuln Agent should have produced hypotheses
    hypotheses = final_state_obj.attack_hypotheses
    assert len(hypotheses) >= 1, "Vuln Agent produced no attack hypotheses"

    # At least one hypothesis should reference Shellshock / CVE-2014-6271
    shocker_hypotheses = [
        h for h in hypotheses
        if (h.cve and "2014-6271" in h.cve)
        or "shellshock" in (h.technique or "").lower()
    ]
    assert len(shocker_hypotheses) >= 1, (
        f"No Shellshock hypothesis found. Hypotheses: "
        f"{[(h.technique, h.cve) for h in hypotheses]}"
    )

    # Save state for inspection after the run.
    save_state_to_disk(engagement_id, final_state_obj)

    # Print findings for manual review (visible with `pytest -s`).
    print(f"\nE2E Test Complete: {engagement_id}")
    print(f"Hosts: {len(hosts)}")
    print(f"Services: {len(services)}")
    print(f"Vulnerabilities: {len(final_state_dict.get('vulnerabilities', []))}")
    print(f"Attack hypotheses: {len(hypotheses)}")
    for h in hypotheses[:3]:
        print(
            f"  #{h.rank}: {h.technique} "
            f"(CVE: {h.cve}, confidence: {h.confidence:.0%})"
        )
