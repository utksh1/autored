"""E2E test: full Phase 1 recon against HackTheBox Lame (10.10.10.5).

This test runs the entire Phase 1 graph against the real Lame box on
HackTheBox, with the real LLM (Claude Sonnet 4.5) and real tools
(nmap, naabu, httpx, nuclei, feroxbuster, subfinder, amass, dnsx,
gobuster). It is **skipped by default** — set ``AUTORED_E2E=1`` to
opt in, and only do so when:

  * You are connected to the HackTheBox VPN (``sudo openvpn user.ovpn``)
  * ``ANTHROPIC_API_KEY`` is set
  * All required CLI tools are installed and on ``$PATH``

Expected runtime: 5-10 minutes. Test passes if nmap discovers ports
21, 22, 445 (FTP, SSH, SMB) and the graph reaches the ``done`` phase.

Usage::

    # 1. Connect to HackTheBox VPN
    sudo openvpn user.ovpn

    # 2. Verify target is reachable
    ping 10.10.10.5

    # 3. Set env vars
    export ANTHROPIC_API_KEY=sk-ant-...
    export AUTORED_E2E=1

    # 4. Run E2E test
    uv run pytest tests/e2e/test_phase1_lame.py -v -s
"""

import asyncio
import os
from pathlib import Path

import pytest

# Skip by default. Use pytest.mark.skipif (NOT skipunless — that's not a
# real pytest marker) with an inverted condition so the test only runs
# when AUTORED_E2E=1 is explicitly set in the environment.
pytestmark = pytest.mark.skipif(
    os.environ.get("AUTORED_E2E") != "1",
    reason="Set AUTORED_E2E=1 to run E2E tests (requires HTB VPN)",
)


@pytest.mark.asyncio
async def test_phase1_lame_recon(tmp_path: Path, monkeypatch):
    """E2E: run full Phase 1 recon against HTB Lame (10.10.10.5).

    Requires:
      * HackTheBox VPN connected
      * ``ANTHROPIC_API_KEY`` set
      * ``nmap``, ``naabu``, ``httpx``, ``nuclei``, ``feroxbuster``,
        ``subfinder``, ``amass``, ``dnsx``, ``gobuster`` installed
      * ``AUTORED_E2E=1`` env var
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
    from autored.graph import build_phase1_graph
    from autored.roe_guard import register_roe
    from autored.logging import setup_logging
    from autored.utils import generate_engagement_id

    monkeypatch.chdir(tmp_path)
    setup_logging(log_dir=str(tmp_path / "logs"))

    # Use a permissive sandbox RoE (allows 0.0.0.0/0) so real tool calls
    # against 10.10.10.5 pass scope enforcement.
    roe = RulesOfEngagement(
        engagement_name="E2E Lame Test",
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

    engagement_id = generate_engagement_id("10.10.10.5", "e2e-lame")
    register_roe(engagement_id, roe)
    init_engagement_folder(engagement_id, "10.10.10.5", "e2e-test")

    state = EngagementState(
        engagement_id=engagement_id,
        target_scope=["10.10.10.5"],
        operator="e2e-test",
        rules_of_engagement=roe,
    )

    checkpointer = await make_checkpointer(engagement_id)
    try:
        graph = build_phase1_graph(checkpointer)
        config = {"configurable": {"thread_id": engagement_id}}

        # Run with real LLM + real tools — should complete in under 10 min.
        # asyncio.wait_for caps it so a hung tool doesn't stall CI forever.
        final_state = await asyncio.wait_for(
            graph.ainvoke(state, config=config),
            timeout=600,
        )
    finally:
        conn = getattr(checkpointer, "conn", None)
        if conn is not None:
            await conn.close()

    # ------------------------------------------------------------------
    # Assertions
    # ------------------------------------------------------------------
    # ``graph.ainvoke`` returns a state-shaped dict in our setup.
    if isinstance(final_state, EngagementState):
        final_state_dict = final_state.model_dump()
        final_state_obj = final_state
    else:
        final_state_dict = final_state
        final_state_obj = EngagementState.model_validate(final_state)

    # Phase should be 'done' (graph reached report_phase1 stub).
    # 'vuln' is also acceptable in case the report_phase1 stub changes.
    assert final_state_dict["phase"] in ("done", "vuln"), (
        f"Expected phase 'done' or 'vuln', got {final_state_dict['phase']!r}"
    )

    hosts = final_state_dict["hosts"]
    assert len(hosts) >= 1, "expected at least 1 host discovered"
    assert any(h["ip"] == "10.10.10.5" for h in hosts), (
        "expected 10.10.10.5 in discovered hosts"
    )

    # Lame should have these ports open: 21 (FTP), 22 (SSH), 445 (SMB).
    services = final_state_dict["services"]
    ports = {s["port"] for s in services}
    assert 21 in ports, f"FTP (21) not discovered; found ports: {sorted(ports)}"
    assert 22 in ports, f"SSH (22) not discovered; found ports: {sorted(ports)}"
    assert 445 in ports, f"SMB (445) not discovered; found ports: {sorted(ports)}"

    # Save state for inspection after the run.
    save_state_to_disk(engagement_id, final_state_obj)

    # Print findings for manual review (visible with `pytest -s`).
    print(f"\nE2E Test Complete: {engagement_id}")
    print(f"Hosts: {len(hosts)}")
    print(f"Services: {len(services)}")
    print(f"Web apps: {len(final_state_dict.get('web_apps', []))}")
    for s in services:
        print(
            f"  {s['host_ip']}:{s['port']} {s.get('service') or ''} "
            f"{s.get('product') or ''} {s.get('version') or ''}"
        )
