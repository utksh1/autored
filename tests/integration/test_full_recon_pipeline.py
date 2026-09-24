"""Phase 1, Task 28 — Integration test: full recon pipeline, mocked.

End-to-end test that mocks both the LLM (``call_with_fallback("plan_recon")``,
spec §4.3) and the subprocess layer (``run_subprocess`` in every tool
module) and then runs the full Phase 1 graph (``build_phase1_graph``)
against the Lame fixtures from Batches A-C.

Verifies that the full chain still works as a single unit:

1. ``roe_gate_start`` registers (or re-confirms) the RoE.
2. ``recon_node`` calls ``call_with_fallback("plan_recon", prompt)`` —
   mocked to return ``recon_plan_lame.json`` (3 steps: portscan,
   webenum, dnsenum).
3. The plan dispatches ``portscan_subagent`` (naabu + nmap),
   ``webenum_subagent`` (httpx + feroxbuster + nuclei) and
   ``dnsenum_subagent`` (dnsx) — each tool wrapper's
   ``run_subprocess`` call is mocked to return the matching fixture
   file (``nmap_lame_quick.xml``, ``naabu_lame.jsonl``, etc.).
4. ``recon_node`` merges the sub-agent outputs back into state shape
   (``hosts``, ``services``, ``web_apps``, ``directories``,
   ``subdomains``) and advances ``phase`` to ``"vuln"``.
5. The conditional edge routes to ``report_phase1`` (because hosts is
   non-empty), which sets ``phase = "done"``.
6. The graph terminates.

Asserts the final state has the Lame host, at least 2 services (the
nmap fixture has 5 open ports — 21, 22, 139, 445, 3632 — so this is
trivially true), and that at least one ``*.out`` raw artefact landed
in ``engagements/<id>/raw/``.

The brief sketches ``RulesOfEngagement.model_validate_yaml(path)`` —
Pydantic v2 has no such method (only ``model_validate_json``). The
real loader is ``autored.config.load_roe(path)`` (used by the T22
recon-agent integration test), so we use that here.

Patching ``run_subprocess`` — each tool module imports
``run_subprocess`` into its own namespace at module-load time
(``from autored.subprocess_runner import run_subprocess``), so
patching ``autored.subprocess_runner.run_subprocess`` alone does NOT
intercept calls dispatched through the tool wrappers. We patch the
binding in every Phase 1 tool module instead. (Only 6 of the 9 tools
are exercised by the fixture plan — portscan, webenum and dnsenum —
but patching all 9 keeps the test resilient if the LLM-mock plan
changes.)
"""
from unittest.mock import AsyncMock, patch

import pytest

from autored.agents.recon import recon_node  # noqa: F401  (import-side effect check)
from autored.config import load_roe
from autored.graph import build_phase1_graph
from autored.logging import setup_logging
from autored.persistence.filesystem import init_engagement_folder
from autored.persistence.sqlite_saver import make_checkpointer
from autored.roe_guard import register_roe
from autored.state import EngagementState
from autored.subprocess_runner import SubprocessResult


@pytest.mark.asyncio
async def test_full_recon_pipeline_mocked(
    tmp_path, monkeypatch, sandbox_roe_yaml, fixtures_dir
):
    # Run inside tmp_path so engagements/ + logs/ never touch the repo.
    monkeypatch.chdir(tmp_path)
    setup_logging(log_dir=str(tmp_path / "logs"))

    # --- Register RoE -----------------------------------------------------
    roe = load_roe(sandbox_roe_yaml)
    engagement_id = "test-pipeline-001"
    register_roe(engagement_id, roe)

    # --- Init engagement folder ------------------------------------------
    init_engagement_folder(engagement_id, "10.10.10.5", "test")

    # --- Mock the LLM ----------------------------------------------------
    plan_json = (
        fixtures_dir / "llm_responses" / "recon_plan_lame.json"
    ).read_text()
    # ``recon_node`` calls ``call_with_fallback("plan_recon", prompt)``
    # (spec §4.3). ``call_with_fallback`` returns ``str``, not a
    # message object, so the mock returns ``plan_json`` directly.

    # --- Mock run_subprocess per-tool (returns fixture output) ----------
    nmap_xml = (fixtures_dir / "nmap_lame_quick.xml").read_text()
    naabu_jsonl = (fixtures_dir / "naabu_lame.jsonl").read_text()
    httpx_json = (fixtures_dir / "httpx_lame.json").read_text()
    nuclei_jsonl = (fixtures_dir / "nuclei_lame.jsonl").read_text()
    feroxbuster_json = (fixtures_dir / "feroxbuster_lame.json").read_text()
    subfinder_json = (fixtures_dir / "subfinder_lame.json").read_text()
    amass_json = (fixtures_dir / "amass_lame.json").read_text()
    dnsx_json = (fixtures_dir / "dnsx_lame.json").read_text()
    gobuster_vhost_txt = (fixtures_dir / "gobuster_vhost_lame.txt").read_text()

    async def mock_run_subprocess(cmd, timeout: int = 600) -> SubprocessResult:
        cmd_str = " ".join(cmd)
        if "nmap" in cmd_str:
            stdout = nmap_xml
        elif "naabu" in cmd_str:
            stdout = naabu_jsonl
        elif "httpx" in cmd_str:
            stdout = httpx_json
        elif "nuclei" in cmd_str:
            stdout = nuclei_jsonl
        elif "feroxbuster" in cmd_str:
            stdout = feroxbuster_json
        elif "subfinder" in cmd_str:
            stdout = subfinder_json
        elif "amass" in cmd_str:
            stdout = amass_json
        elif "dnsx" in cmd_str:
            stdout = dnsx_json
        elif "gobuster" in cmd_str:
            stdout = gobuster_vhost_txt
        else:
            stdout = ""
        return SubprocessResult(
            stdout=stdout,
            stderr="",
            returncode=0,
            duration_sec=1.0,
            command=cmd_str,
        )

    # --- Build initial state --------------------------------------------
    state = EngagementState(
        engagement_id=engagement_id,
        target_scope=["10.10.10.5"],
        operator="test",
        rules_of_engagement=roe,
    )

    # --- Patch LLM + run_subprocess in every tool module ----------------
    tool_modules = [
        "autored.tools.nmap",
        "autored.tools.naabu",
        "autored.tools.httpx_tool",
        "autored.tools.nuclei",
        "autored.tools.feroxbuster",
        "autored.tools.subfinder",
        "autored.tools.amass",
        "autored.tools.dnsx",
        "autored.tools.gobuster_vhost",
    ]

    patchers = [patch(m + ".run_subprocess", side_effect=mock_run_subprocess)
                for m in tool_modules]
    for p in patchers:
        p.start()
    try:
        with patch("autored.agents.recon.call_with_fallback",
                   new=AsyncMock(return_value=plan_json)):
            # --- Build and run graph ----------------------------------
            checkpointer = await make_checkpointer(engagement_id)
            graph = build_phase1_graph(checkpointer)
            config = {"configurable": {"thread_id": engagement_id}}
            final_state = await graph.ainvoke(state, config=config)
    finally:
        for p in patchers:
            p.stop()

    # --- Verify final state ---------------------------------------------
    assert final_state["phase"] == "done"  # went through report_phase1 stub
    assert len(final_state["hosts"]) >= 1
    assert any(h.ip == "10.10.10.5" for h in final_state["hosts"])
    # nmap fixture has 5 open ports (21, 22, 139, 445, 3632); >=2 is the floor.
    assert len(final_state["services"]) >= 2
    # --- Verify raw outputs were saved ----------------------------------
    raw_dir = tmp_path / "engagements" / engagement_id / "raw"
    assert raw_dir.exists()
    assert len(list(raw_dir.glob("*.out"))) >= 1
