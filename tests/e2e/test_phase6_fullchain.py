"""Phase 6, Task 18 — E2E test: full kill chain against GoAD, ending in
deliverables + cross-engagement memory rows.

This module is **skipped by default**. Set ``AUTORED_E2E=1`` to opt in.

Spec §13.6 ship criteria:
- Full kill chain runs end-to-end **without intervention** in sandbox mode
  (recon → vuln → exploit → post-ex → lateral → cleanup → report).
- Report deliverables (markdown + PDF, when WeasyPrint is available) are
  generated for the engagement.
- Cross-engagement memory rows are written to ``db/engagements.sqlite``
  and ``db/chroma`` at report time.

Gated identically to the Phase 1–5 E2E tests (``AUTORED_E2E=1`` +
``AUTORED_LHOST`` + ``AUTORED_GOAD_TARGET`` + the GoAD lab + msfrpcd +
impacket + bloodhound-python + Neo4j + crackmapexec + chisel + ligolo-ng
+ sshpass + API keys + all 10 Phase 1 recon CLI tools). Mirrors the
Phase 5 GoAD multi-host E2E test in structure; extends the assertion
lattice through the Report Agent (markdown + PDF + lessons + SQLite
engagements row) and the live secret-redaction re-check (Review Focus
#2, spec §3.3).

Run
---
    AUTORED_E2E=1 uv run pytest tests/e2e/test_phase6_fullchain.py -v -s

Expected runtime: 60-120 minutes against GoAD (the full kill chain +
report generation; the report node itself is ~30-60s of LLM time on top
of the Phase 5 runtime). The test passes if all of the spec §13.6 ship
criteria hold:

- The chain terminates with ``phase == "done"``.
- At least one verified foothold was achieved (``footholds`` non-empty).
- ``report_paths`` is not ``None`` and ``report.md`` exists & is
  non-empty.
- ``lessons.json`` exists.
- ``report.pdf`` starts with the ``%PDF-`` magic bytes (only when
  WeasyPrint is available; ``pdf_path is None`` is a legal degraded
  state).
- No harvested secret value appears verbatim in the report text (live
  re-check, not just the writer's redaction pass).
- The SQLite ``engagements`` table has exactly 1 row for the
  engagement.
- Every cleanup result is verified (Phase 5 regression).
- Every sub-engagement referenced from the parent state has its
  ``state.json`` persisted on disk at ``sub_state_path``.
"""
import os

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("AUTORED_E2E") != "1",
    reason=(
        "E2E test requires AUTORED_E2E=1 + live GoAD lab + API keys "
        "+ msfrpcd + impacket + bloodhound-python + Neo4j + "
        "crackmapexec + chisel + ligolo-ng + sshpass"
    ),
)

GOAD_TARGET = os.environ.get("AUTORED_GOAD_TARGET", "192.168.56.22")
LHOST = os.environ.get("AUTORED_LHOST", "192.168.56.1")


async def test_phase6_full_chain_with_report():
    """E2E: full Phase 6 graph (recon + vuln + exploit + postex +
    lateral + cleanup + report) against GoAD, ending in deliverables.

    Targets the canonical GoAD primary (default ``192.168.56.22`` /
    SRV02 — override via ``AUTORED_GOAD_TARGET``). The chain exercises
    every node from the spec §2.3 topology and ends in the Report
    Agent, which assembles the executive summary + technical report +
    MITRE ATT&CK matrix, renders the PDF (when WeasyPrint is
    available), and persists findings + sha256-hashed credentials +
    lessons into the cross-engagement memory store.

    Requires:
    - GoAD lab deployed and reachable (``ping 192.168.56.22``).
    - ANTHROPIC_API_KEY and DEEPSEEK_API_KEY set.
    - All 10 Phase 1 recon CLI tools installed and on PATH.
    - msfrpcd running on 127.0.0.1:55553 with password 'msf'.
    - impacket + bloodhound-python installed.
    - Neo4j running for BloodHound ingestion.
    - crackmapexec, chisel, ligolo-ng, sshpass on PATH.
    - AUTORED_LHOST set to the operator's VirtualBox host-only IP.
    - AUTORED_E2E=1 env var.
    """
    # Imports kept inside the test body so a missing dependency at
    # module load doesn't poison collection when AUTORED_E2E is unset
    # (the lazy-import convention from the Phase 1-5 E2E tests).
    import asyncio
    import shutil
    from pathlib import Path

    from autored.graph import build_phase6_graph
    from autored.models.roe import RulesOfEngagement
    from autored.persistence.filesystem import (
        save_state_to_disk,
        init_engagement_folder,
    )
    from autored.persistence.sqlite_saver import make_checkpointer
    from autored.roe_guard import register_roe
    from autored.state import EngagementState
    from autored.tui.event_bus import EventBus

    engagement_id = "e2e-phase6-fullchain"

    # Sandbox RoE narrowed to the GoAD subnet — never run E2E against
    # production. ``allowed_techniques=["*"]`` so the Lateral Agent's
    # pivots and the Cleanup Agent's removal commands aren't RoE-
    # blocked. ``hitl_mode="auto_approve"`` so the operator doesn't
    # have to sit at the TUI for 60-120 minutes; the gates short-
    # circuit and the run completes unattended. (For an interactive
    # E2E with HitL gates, set ``hitl_mode="always_ask"`` and run
    # with ``--tui``.)
    roe = RulesOfEngagement(
        engagement_name="Phase 6 E2E",
        operator="e2e",
        operator_signature="e2e",
        allowed_ips=["192.168.56.0/24"],
        allowed_techniques=["*"],
        persistence_allowed=True,
        evasion_allowed=True,
        exfiltration_allowed=True,
        data_destruction_allowed=False,
        kernel_exploits_allowed=True,
        hitl_mode="auto_approve",
    )

    register_roe(engagement_id, roe)
    init_engagement_folder(engagement_id, GOAD_TARGET, roe.operator)

    state = EngagementState(
        engagement_id=engagement_id,
        target_scope=[GOAD_TARGET],
        operator=roe.operator,
        rules_of_engagement=roe,
    )
    state.event_bus = EventBus()

    async def _run():
        checkpointer = await make_checkpointer(engagement_id)
        graph = build_phase6_graph(checkpointer)
        config = {"configurable": {"thread_id": engagement_id}}
        try:
            # 90 minutes — the full kill chain plus report
            # generation. Generous timeout so a slow LLM / slow GoAD
            # VM doesn't flake the test; the run itself usually
            # finishes in 60-90 min.
            return await asyncio.wait_for(
                graph.ainvoke(state, config=config), timeout=5400,
            )
        finally:
            conn = getattr(checkpointer, "conn", None)
            if conn is not None:
                await conn.close()

    final_state = await _run()
    if isinstance(final_state, dict):
        from autored.state import EngagementState as ES

        final_state = ES.model_validate(final_state)

    # Persist the final state for manual inspection.
    save_state_to_disk(engagement_id, final_state)

    # ---- Ship criterion 1: the chain completed -------------------
    assert final_state.phase == "done", (
        f"chain did not reach 'done' phase (got {final_state.phase!r})"
    )
    assert final_state.footholds, "no foothold achieved — chain incomplete"

    # ---- Ship criterion 2: deliverables exist ---------------------
    report_paths = final_state.report_paths
    assert report_paths is not None, "report_paths is None — Report Agent did not run"
    assert Path(report_paths.markdown_path).exists(), (
        f"report.md not found at {report_paths.markdown_path}"
    )
    assert Path(report_paths.markdown_path).stat().st_size > 0, (
        "report.md is empty — Report Agent wrote nothing"
    )
    assert Path(report_paths.lessons_path).exists(), (
        f"lessons.json not found at {report_paths.lessons_path}"
    )
    # ``pdf_path is None`` is legal when WeasyPrint is unavailable
    # (Review Focus #5 — graceful degradation). When a path is set,
    # verify the magic bytes so we never silently ship a 0-byte or
    # HTML-redirect "PDF".
    if report_paths.pdf_path:
        pdf_bytes = Path(report_paths.pdf_path).read_bytes()
        assert pdf_bytes[:5] == b"%PDF-", (
            f"report.pdf does not start with %PDF- magic bytes "
            f"(got {pdf_bytes[:5]!r})"
        )

    # No secret material in the deliverables (Review Focus #2, live
    # re-check against ``harvested_secrets`` — the markdown writer
    # redacts on its side, this asserts the redaction actually held).
    report_text = Path(report_paths.markdown_path).read_text()
    for secret in final_state.harvested_secrets:
        assert secret.secret_value not in report_text, (
            f"plaintext secret value from {secret.source} "
            f"({secret.secret_type}) found verbatim in report.md "
            f"— redaction failed"
        )

    # ---- Ship criterion 3: cross-engagement memory rows -----------
    # The Report Agent calls ``persist_engagement_memory`` at report
    # time, which writes the engagements row + findings + credentials
    # + lessons to ``db/engagements.sqlite`` and Chroma upserts to
    # ``db/chroma``. Assert the engagements row landed — the canonical
    # "the chain ran end to end and the memory is wired" check.
    import aiosqlite

    async with aiosqlite.connect("db/engagements.sqlite") as db:
        cursor = await db.execute(
            "SELECT COUNT(*) FROM engagements WHERE id = ?", (engagement_id,)
        )
        (count,) = await cursor.fetchone()
        assert count == 1, (
            f"expected exactly 1 engagements row for {engagement_id}, "
            f"got {count}"
        )

    # ---- Ship criterion 4: sub-engagements persisted on disk -----
    # Phase 5 regression — every linked sub-engagement must have its
    # state.json on disk at the recorded path (spec §13.5).
    for ref in final_state.sub_engagements:
        assert os.path.exists(ref.sub_state_path), (
            f"sub-engagement state not persisted at {ref.sub_state_path}"
        )

    # ---- Ship criterion 5: cleanup happened (Phase 5 regression) -
    if final_state.cleanup_results:
        assert all(c.verified for c in final_state.cleanup_results), (
            "cleanup left unverified artifacts — see report for inventory"
        )

    # Print findings for manual review (-s to see stdout).
    print(f"\n[Phase 6 E2E] engagement: {engagement_id}")
    print(f"  phase: {final_state.phase}")
    print(f"  footholds: {len(final_state.footholds)}")
    print(
        f"  report_paths: md={report_paths.markdown_path} "
        f"pdf={report_paths.pdf_path} lessons={report_paths.lessons_path}"
    )
    print(f"  harvested_secrets: {len(final_state.harvested_secrets)}")
    print(f"  cleanup_results: {len(final_state.cleanup_results)} (all verified: "
          f"{all(c.verified for c in final_state.cleanup_results)})")
    print(f"  sub_engagements: {len(final_state.sub_engagements)}")

    # Cleanup the engagement folder this test created (the SQLite row
    # is intentionally left behind — it's the cross-engagement memory
    # the next run will query).
    shutil.rmtree(Path("engagements") / engagement_id, ignore_errors=True)
