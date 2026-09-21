"""E2E test: full Phase 3 (recon + vuln + exploit) against HackTheBox Blue (10.10.10.40).

This test runs the entire Phase 3 graph against the real Blue box on
HackTheBox, with the real LLMs (Claude Sonnet 4.5 for synthesis +
exploit planning, DeepSeek 3.2 for second opinion) and real tools
(nmap, naabu, httpx, nuclei, feroxbuster, subfinder, amass, dnsx,
gobuster, searchsploit, **Metasploit RPC**). It is **skipped by
default** — set ``AUTORED_E2E=1`` to opt in, and only do so when:

  * You are connected to the HackTheBox VPN (``sudo openvpn user.ovpn``)
  * ``ANTHROPIC_API_KEY`` and ``DEEPSEEK_API_KEY`` are set
  * All required CLI recon tools are installed and on ``$PATH``
  * ``msfrpcd`` is running on ``127.0.0.1:55553`` with password ``msf``::

      msfrpcd -P msf -p 55553 -a 127.0.0.1 -U msf -L

    (See README.md → "Phase 3 E2E Test (Blue)" for the full setup.)

Expected runtime: 15–30 minutes (recon + vuln + Metasploit exploit).
Test passes if:

  * nmap discovers port 445 (SMB) on Blue
  * The Vuln Agent produces at least one EternalBlue (MS17-010) hypothesis
  * The Exploit Agent's MSF sub-agent executes the
    ``exploit/windows/smb/ms17_010_eternalblue`` module and obtains a
    Meterpreter session
  * The foothold is recorded in the final state

Usage::

    # 1. Connect to HackTheBox VPN
    sudo openvpn user.ovpn

    # 2. Verify Blue is reachable
    ping 10.10.10.40

    # 3. Start msfrpcd (Metasploit RPC daemon)
    msfrpcd -P msf -p 55553 -a 127.0.0.1 -U msf -L

    # 4. Find your HTB VPN IP (this is the LHOST the reverse shell will
    #    connect back to — must be reachable from the target)
    ip addr show tun0 | grep "inet "

    # 5. Set env vars (replace 10.10.14.5 with your tun0 IP)
    export ANTHROPIC_API_KEY=sk-ant-...
    export DEEPSEEK_API_KEY=sk-...
    export AUTORED_E2E=1
    export AUTORED_LHOST=10.10.14.5

    # 6. Run E2E test (use -s to see live findings + hypothesis + exploit)
    uv run pytest tests/e2e/test_phase3_blue.py -v -s
"""

import asyncio
import os
from pathlib import Path

import pytest

# Skip by default — only opt in with AUTORED_E2E=1 (and even then,
# only run when connected to HTB VPN with API keys set + msfrpcd running).
pytestmark = pytest.mark.skipif(
    os.environ.get("AUTORED_E2E") != "1",
    reason="Set AUTORED_E2E=1 to run E2E tests (requires HTB VPN + msfrpcd)",
)


@pytest.mark.asyncio
async def test_phase3_blue_recon_vuln_exploit(tmp_path: Path, monkeypatch):
    """E2E: run full Phase 3 (recon + vuln + exploit) against HTB Blue (10.10.10.40).

    Requires:
      * HackTheBox VPN connected
      * ``ANTHROPIC_API_KEY`` and ``DEEPSEEK_API_KEY`` set
      * ``nmap``, ``naabu``, ``httpx``, ``nuclei``, ``feroxbuster``,
        ``subfinder``, ``amass``, ``dnsx``, ``gobuster``, ``searchsploit``
        installed and on ``$PATH``
      * ``msfrpcd`` running on ``127.0.0.1:55553`` with password ``msf``
        (start with: ``msfrpcd -P msf -p 55553 -a 127.0.0.1 -U msf -L``)
      * ``AUTORED_LHOST`` env var set to your HTB VPN IP (tun0)
      * ``AUTORED_E2E=1`` env var

    Expected outcome:
      * Recon discovers port 445 (SMB) on 10.10.10.40
      * Vuln Agent identifies EternalBlue (MS17-010 / CVE-2017-0144)
      * Exploit Agent dispatches msfagent → ms17_010_eternalblue module
      * Foothold recorded (phase="postex" or "done")
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
    from autored.graph import build_phase3_graph
    from autored.roe_guard import register_roe
    from autored.logging import setup_logging
    from autored.utils import generate_engagement_id
    from autored.tui.event_bus import EventBus

    lhost = os.environ.get("AUTORED_LHOST")
    if not lhost:
        pytest.fail(
            "AUTORED_LHOST env var must be set to your HTB VPN IP (tun0). "
            "Find it with: ip addr show tun0 | grep 'inet '"
        )

    monkeypatch.chdir(tmp_path)
    setup_logging(log_dir=str(tmp_path / "logs"))

    # Permissive sandbox RoE (0.0.0.0/0) so real tool calls against
    # 10.10.10.40 pass scope enforcement. hitl_mode="auto_approve"
    # so the Exploit Agent doesn't block waiting for a TUI response
    # (the operator pre-approves by setting AUTORED_E2E=1).
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
    # Phase 3: every engagement needs an EventBus on the state so the
    # Exploit Agent's HitL gates have somewhere to emit (auto-approve
    # in sandbox mode means it won't block on operator input).
    state.event_bus = EventBus()

    checkpointer = await make_checkpointer(engagement_id)
    try:
        graph = build_phase3_graph(checkpointer)
        config = {"configurable": {"thread_id": engagement_id}}

        # 30-minute cap so a hung tool doesn't stall CI forever.
        # Phase 3 is longer than Phase 2 because the Exploit Agent
        # runs the full Metasploit RPC exploit flow (login → execute
        # → session check) which can take several minutes against a
        # live target.
        final_state = await asyncio.wait_for(
            graph.ainvoke(state, config=config),
            timeout=1800,
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
    # exploit_node set phase='postex') or 'postex' (if the report
    # stub's behaviour changes in Phase 4 to preserve postex).
    assert final_state_dict["phase"] in ("done", "postex"), (
        f"Expected phase 'done' or 'postex', got {final_state_dict['phase']!r}"
    )

    hosts = final_state_dict["hosts"]
    assert len(hosts) >= 1, "expected at least 1 host discovered"
    assert any(h["ip"] == "10.10.10.40" for h in hosts), (
        "expected 10.10.10.40 in discovered hosts"
    )

    # Blue should have port 445 open (SMB — the EternalBlue attack surface).
    services = final_state_dict["services"]
    ports = {s["port"] for s in services}
    assert 445 in ports, f"Port 445 (SMB) not found in services: {sorted(ports)}"

    # Vuln Agent should have produced EternalBlue as a hypothesis.
    hypotheses = final_state_obj.attack_hypotheses
    assert len(hypotheses) >= 1, "Vuln Agent produced no attack hypotheses"

    eternalblue_hypotheses = [
        h for h in hypotheses
        if (h.cve and "2017-0144" in h.cve)
        or "ms17_010" in (h.tool_module or "").lower()
        or "eternalblue" in (h.technique or "").lower()
    ]
    assert len(eternalblue_hypotheses) >= 1, (
        f"No EternalBlue hypothesis found. Hypotheses: "
        f"{[(h.technique, h.cve, h.tool_module) for h in hypotheses]}"
    )

    # Exploit Agent should have recorded at least one foothold.
    footholds = final_state_obj.footholds
    assert len(footholds) >= 1, (
        "Exploit Agent recorded no foothold — Metasploit exploit failed "
        "or _verify_foothold didn't see a session_id"
    )

    # The foothold's method should reference ms17_010 (derived from the
    # exploit module path by _derive_method_name in exploit.py).
    methods = {f.method for f in footholds}
    assert "ms17_010" in methods, (
        f"Expected foothold method 'ms17_010', got: {methods}"
    )

    # Save state for inspection after the run.
    save_state_to_disk(engagement_id, final_state_obj)

    # Print findings for manual review (visible with `pytest -s`).
    print(f"\nE2E Test Complete: {engagement_id}")
    print(f"Hosts: {len(hosts)}")
    print(f"Services: {len(services)}")
    print(f"Attack hypotheses: {len(hypotheses)}")
    print(f"Footholds: {len(footholds)}")
    for h in hypotheses[:3]:
        print(
            f"  #{h.rank}: {h.technique} "
            f"(CVE: {h.cve}, tool: {h.tool}, confidence: {h.confidence:.0%})"
        )
    for f in footholds:
        print(
            f"  foothold: host={f.host_ip} method={f.method} "
            f"context={f.context} established_at={f.established_at}"
        )
