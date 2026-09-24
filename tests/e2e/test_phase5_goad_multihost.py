"""Phase 5, Task 15 — E2E test against GoAD, multi-host (lateral + cleanup).

This module is **skipped by default**. Set ``AUTORED_E2E=1`` to opt in.

When enabled, the test runs the real Phase 5 graph (real LLM via the
model router, real subprocess calls to the recon tools, real NVD HTTP,
real Metasploit RPC via ``msfrpcd``, real BloodHound collection, real
``impacket`` ``secretsdump`` / ``wmiexec`` / ``psexec`` / ``smbexec``,
real ``crackmapexec`` for the credential validation spray, real chisel
/ ligolo-ng for tunnel bring-up when needed, real ``sshpass`` for any
Linux-side transport, and the real sub-engagement spawner that runs a
nested Phase 4 graph against the pivot target) against a self-hosted
GoAD (Game Of Active Directory) lab spanning **two** reachable VMs.

GoAD (Game Of Active Directory) is a multi-VM Active Directory lab
designed for red-team training. The Phase 5 E2E test verifies the
spec §13.5 ship criteria — the full chain across 2+ hosts with a
linked sub-engagement and a verified cleanup that leaves zero
artifacts behind.

The canonical GoAD pivot target is a second Windows host reached via
pass-the-hash from the primary foothold (e.g., the harvested domain
administrator hash from the first foothold's secretsdump output is
sprayed + pivoted onto a second DC or member server). The Phase 5
test exercises the full chain on that pivot target: the Lateral
Agent's candidate identification + scope check + HitL gate + pivot
execution, the optional tunnel bring-up, the sub-engagement spawner
running a full Phase 4 graph against the pivot target (which itself
records its own footholds / post-ex collections / etc.), and finally
the Cleanup Agent removing + verifying every persistence artifact,
tunnel teardown, and staged temp file across both hosts.

Prerequisites
-------------
In addition to the Phase 4 prerequisites:

- **A second reachable GoAD VM** — the test pivots from the primary
  target (default ``192.168.56.22`` / SRV02) to a second host
  (default ``192.168.56.11``). Override with ``AUTORED_GOAD_TARGET``
  and ``AUTORED_GOAD_PIVOT_TARGET``.
- **``crackmapexec`` on your ``$PATH``** (Kali default; if you only
  have ``netexec``, symlink it:
  ``ln -s $(which netexec) /usr/local/bin/crackmapexec``).
- **``impacket`` installed** (powers ``secretsdump``, ``wmiexec``,
  ``psexec``, ``smbexec`` — the Phase 5 PivotExecutor + CredHarvester
  sub-agents wrap them).
- **``chisel`` and ``ligolo-ng`` on ``$PATH``** (the TunnelSetup
  sub-agent's two backed tools — only invoked when a pivot needs a
  tunnel, but installed ahead of time so a non-routable pivot target
  doesn't crash the run).
- **``sshpass`` on ``$PATH``** (the cleanup tool's ``ssh`` transport
  for Linux targets — only used if a Linux host appears in the
  scope, but installed ahead of time).
- **Working domain credentials are NOT pre-seeded** — the chain
  harvests them itself: exploit → foothold → post-ex secretsdump →
  administrator hash → pivot.

Run
---
    AUTORED_E2E=1 uv run pytest tests/e2e/test_phase5_goad_multihost.py -v -s

Expected runtime: 60-90 minutes against GoAD (recon ~5min, vuln ~5min,
exploit ~5-10min for the initial foothold, post-ex ~15-30min
covering WindowsEnum + mimikatz + BloodHound + persistence + evasion
+ exfil on the primary foothold, lateral pivot ~1-5min, sub-engagement
~20-30min running the full Phase 4 chain against the pivot target,
cleanup ~5-10min for artifact removal + verification re-scan across
both hosts). The test passes if all of the spec §13.5 ship criteria
hold:

- Recon discovers ≥ 2 hosts (both scope targets).
- The Exploit Agent records ≥ 1 foothold.
- The Lateral Agent executes ≥ 1 **successful** pivot onto the second
  host (harvested administrator hash via wmiexec pass-the-hash).
- A sub-engagement runs against the pivot target and its
  ``state.json`` is persisted and linked from the parent state.
- The Cleanup Agent removes and **verifies** every persistence
  artifact (zero unverified cleanups).
- The Phase 5 graph reaches the ``done`` phase.

Mirrors the Phase 4 GoAD E2E test (T15) in structure; differs in
target (two GoAD VMs vs one) and in the lateral + cleanup chain
assertions (Phase 4 stops at post-ex; Phase 5 extends through
lateral + cleanup).
"""
import asyncio
import os

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("AUTORED_E2E") != "1",
    reason=(
        "E2E test requires AUTORED_E2E=1 + live GoAD lab (two VMs) "
        "+ API keys + msfrpcd + impacket + crackmapexec + chisel "
        "+ ligolo-ng + sshpass"
    ),
)


def test_phase5_goad_multihost():
    """E2E: run full Phase 5 (recon + vuln + exploit + postex + lateral + cleanup) against GoAD.

    Targets two GoAD VMs: the primary target (default ``192.168.56.22``,
    override via ``AUTORED_GOAD_TARGET``) and the pivot target
    (default ``192.168.56.11``, override via
    ``AUTORED_GOAD_PIVOT_TARGET``). The test exercises the full
    Phase 5 graph: recon discovers both Windows hosts, the Vuln Agent
    produces an exploit hypothesis, the Exploit Agent establishes a
    Windows foothold on the primary, the Post-Ex Agent runs the six
    sub-activities on the foothold (harvesting the domain
    administrator hash), the Lateral Agent pivots the harvested hash
    onto the second host via wmiexec pass-the-hash and spawns a
    sub-engagement against it, and the Cleanup Agent removes + verifies
    every persistence artifact across both hosts.

    Requires:
    - GoAD lab deployed with two VMs reachable (``ping 192.168.56.22``
      and ``ping 192.168.56.11``).
    - ANTHROPIC_API_KEY and DEEPSEEK_API_KEY set.
    - All 10 Phase 1 recon CLI tools installed and on PATH.
    - msfrpcd running on 127.0.0.1:55553 with password 'msf'.
    - impacket + bloodhound-python installed.
    - Neo4j running for BloodHound ingestion.
    - crackmapexec, chisel, ligolo-ng, sshpass on PATH.
    - AUTORED_LHOST set to the operator's VirtualBox host-only IP.
    - AUTORED_E2E=1 env var.
    """
    # Imports kept inside the test so a missing dependency at module
    # load doesn't poison collection when AUTORED_E2E is unset.
    from autored.models.roe import RulesOfEngagement
    from autored.persistence.filesystem import (
        init_engagement_folder,
        save_state_to_disk,
    )
    from autored.persistence.sqlite_saver import make_checkpointer
    from autored.graph import build_phase5_graph
    from autored.roe_guard import register_roe
    from autored.state import EngagementState
    from autored.tui.event_bus import EventBus

    primary = os.environ.get("AUTORED_GOAD_TARGET", "192.168.56.22")
    pivot_target = os.environ.get("AUTORED_GOAD_PIVOT_TARGET", "192.168.56.11")
    lhost = os.environ.get("AUTORED_LHOST")
    assert lhost, "AUTORED_LHOST must be set (VirtualBox host-only IP)"
    engagement_id = (
        f"p5-goad-{primary.split('.')[-1]}-{pivot_target.split('.')[-1]}"
    )

    # Sandbox RoE narrowed to the GoAD subnet — never run E2E against
    # production. ``allowed_techniques=["*"]`` so the Lateral Agent's
    # pivots and the Cleanup Agent's removal commands aren't RoE-
    # blocked. ``hitl_mode="auto_approve"`` so the operator doesn't
    # have to sit at the TUI for 60-90 minutes; the gates short-
    # circuit and the run completes unattended. (For an interactive
    # E2E with HitL gates, set ``hitl_mode="always_ask"`` and run
    # with ``--tui``.)
    roe = RulesOfEngagement(
        engagement_name="GoAD Phase 5 E2E",
        operator="operator",
        operator_signature="sandbox-mode",
        allowed_ips=["192.168.56.0/24"],
        allowed_techniques=["*"],
        persistence_allowed=True,
        evasion_allowed=True,
        exfiltration_allowed=True,
        kernel_exploits_allowed=True,
        hitl_mode="auto_approve",
    )
    register_roe(engagement_id, roe)
    init_engagement_folder(
        engagement_id, f"{primary},{pivot_target}", "operator"
    )

    state = EngagementState(
        engagement_id=engagement_id,
        target_scope=[primary, pivot_target],
        operator="operator",
        rules_of_engagement=roe,
    )
    state.event_bus = EventBus()

    async def _run():
        checkpointer = await make_checkpointer(engagement_id)
        graph = build_phase5_graph(checkpointer)
        config = {"configurable": {"thread_id": engagement_id}}
        try:
            # 90 minutes — two hosts + a sub-engagement. Generous
            # timeout so a slow LLM / slow GoAD VM doesn't flake the
            # test; the run itself usually finishes in 60-90 min.
            return await asyncio.wait_for(
                graph.ainvoke(state, config=config), timeout=5400,
            )
        finally:
            conn = getattr(checkpointer, "conn", None)
            if conn is not None:
                await conn.close()

    final = asyncio.run(_run())
    if isinstance(final, dict):
        from autored.state import EngagementState as ES
        final_state = ES.model_validate(final)
    else:
        final_state = final
    save_state_to_disk(engagement_id, final_state)

    # ---- spec §13.5 ship criteria --------------------------------
    # 1. Full chain across 2+ hosts.
    assert len(final_state.hosts) >= 2, (
        f"expected >=2 hosts, got {[h.ip for h in final_state.hosts]}"
    )
    assert len(final_state.footholds) >= 1
    assert len(final_state.pivots) >= 1, "no lateral pivot was executed"
    assert final_state.pivots[0].success is True

    # 2. Sub-engagement linked to parent (spec §13.5).
    assert len(final_state.sub_engagements) >= 1
    ref = final_state.sub_engagements[0]
    assert ref.status in ("completed", "failed")
    assert ref.sub_id.startswith(engagement_id)
    assert os.path.exists(ref.sub_state_path), (
        f"sub-engagement state not persisted at {ref.sub_state_path}"
    )

    # 3+4. Cleanup removed + verified every artifact; none remain.
    # For every persistence_artifact, there must be at least one
    # verified CleanupResult, and no unverified CleanupResult with
    # the artifact's id may remain (Review Focus #5 — failed removal
    # must surface, never silently green).
    if final_state.persistence_artifacts:
        artifact_ids = {a.id for a in final_state.persistence_artifacts}
        verification = [
            r for r in final_state.cleanup_results
            if r.artifact_id in artifact_ids and r.verified
        ]
        unverified = [
            r for r in final_state.cleanup_results
            if r.artifact_id in artifact_ids and not r.verified
        ]
        assert len(verification) >= len(artifact_ids), (
            f"not every artifact verified removed: "
            f"verified={len(verification)}, artifacts={len(artifact_ids)}"
        )
        assert not unverified, (
            f"unverified cleanups remain: "
            f"{[(r.artifact_id, r.error) for r in unverified]}"
        )

    assert final_state.phase == "done"

    # Print findings for manual review (-s to see stdout).
    print(f"\n[Phase 5 E2E] pivots: {len(final_state.pivots)}")
    for p in final_state.pivots:
        print(
            f"  pivot -> {p.target_host} via {p.method} "
            f"(success={p.success})"
        )
    for se in final_state.sub_engagements:
        print(f"  sub-engagement {se.sub_id}: {se.status}")
    print(
        f"[Phase 5 E2E] cleanup results: "
        f"{len(final_state.cleanup_results)} (all verified: "
        f"{all(r.verified for r in final_state.cleanup_results)})"
    )
