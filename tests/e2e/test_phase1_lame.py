"""Phase 1, Task 29 — E2E test against HackTheBox Lame (10.10.10.5).

This module is **skipped by default**. Set ``AUTORED_E2E=1`` to opt in.

When enabled, the test runs the real Phase 1 graph (real LLM via the
model router, real subprocess calls to ``nmap`` / ``naabu`` / ``httpx``
/ ``nuclei`` / ``feroxbuster`` / ``subfinder`` / ``amass`` / ``dnsx``
/ ``gobuster``) against the live HTB Lame target.

Prerequisites
-------------
- HackTheBox VPN connected (``sudo openvpn user.ovpn``).
- ``ANTHROPIC_API_KEY`` (and ``DEEPSEEK_API_KEY`` if fallback is
  exercised) set in the environment.
- All 9 CLI tools installed and on ``PATH``.
- ``AUTORED_E2E=1`` env var.

Run
---
    AUTORED_E2E=1 uv run pytest tests/e2e/test_phase1_lame.py -v -s

Expected runtime: 5-15 minutes (Lame is a slow box to scan).

The test passes if nmap discovers the canonical Lame open ports
21 (ftp), 22 (ssh), and 445 (smb), and the graph terminates with
``phase`` in (``done``, ``vuln``).
"""
import os

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("AUTORED_E2E") != "1",
    reason="E2E test requires AUTORED_E2E=1 + live HTB VPN",
)


@pytest.mark.asyncio
async def test_phase1_lame_recon(tmp_path, monkeypatch):
    """E2E: run full Phase 1 recon against HTB Lame (10.10.10.5).

    Requires:
    - HackTheBox VPN connected
    - ANTHROPIC_API_KEY set
    - nmap, naabu, httpx, nuclei, feroxbuster, subfinder, amass, dnsx,
      gobuster installed and on PATH
    - AUTORED_E2E=1 env var
    """
    # Imports kept inside the test so a missing dependency at module
    # load doesn't poison collection when AUTORED_E2E is unset.
    from autored.config import RulesOfEngagement
    from autored.graph import build_phase1_graph
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
    graph = build_phase1_graph(checkpointer)
    config = {"configurable": {"thread_id": engagement_id}}

    # Run with real LLM and real tools — completes in under 10-15 min
    final_state = await graph.ainvoke(state, config=config)

    # Assertions
    assert final_state["phase"] in ("done", "vuln")
    assert len(final_state["hosts"]) >= 1
    assert any(h.ip == "10.10.10.5" for h in final_state["hosts"])

    # Lame should have these ports open: 21 (FTP), 22 (SSH), 445 (SMB)
    services = final_state["services"]
    ports = {s.port for s in services}
    assert 21 in ports, f"FTP (21) not discovered; ports={ports}"
    assert 22 in ports, f"SSH (22) not discovered; ports={ports}"
    assert 445 in ports, f"SMB (445) not discovered; ports={ports}"

    # Save state for inspection
    save_state_to_disk(
        engagement_id, EngagementState.model_validate(final_state)
    )

    # Print findings for manual review (-s to see stdout)
    print(f"\nE2E Test Complete: {engagement_id}")
    print(f"Hosts: {len(final_state['hosts'])}")
    print(f"Services: {len(services)}")
    print(f"Web apps: {len(final_state['web_apps'])}")
    for s in services:
        print(
            f"  {s.host_ip}:{s.port} {s.service} "
            f"{s.product or ''} {s.version or ''}"
        )
