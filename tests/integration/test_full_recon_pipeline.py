"""End-to-end integration test for the full Phase 1 recon pipeline.

Mocks the LLM (returns the ``recon_plan_lame.json`` fixture) and every
tool subprocess call (returns canned fixture data per command name),
then runs the full Phase 1 LangGraph end-to-end::

    roe_gate_start  ->  recon  ->  report_phase1  ->  END

Verifies:
  * Final state phase is ``"done"`` (went through ``report_phase1`` stub)
  * At least 1 host found (``10.10.10.5``)
  * At least 2 services found (ftp + ssh + ...)
  * Raw tool outputs were saved to ``engagements/<id>/raw/``

This is the moment-of-truth test for Phase 1: if every prior task
(state schema, RoE guard, model router, sub-agents, tools, graph
orchestrator, persistence) is wired correctly, this passes.
"""

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from autored.state import EngagementState
from autored.models.roe import RulesOfEngagement
from autored.persistence.filesystem import init_engagement_folder
from autored.persistence.sqlite_saver import make_checkpointer
from autored.graph import build_phase1_graph
from autored.roe_guard import register_roe
from autored.logging import setup_logging


@pytest.mark.asyncio
async def test_full_recon_pipeline_mocked(
    tmp_path: Path,
    monkeypatch,
    sandbox_roe_yaml: str,
    fixtures_dir: Path,
):
    """Run the full Phase 1 graph with mocked LLM + mocked subprocesses."""
    monkeypatch.chdir(tmp_path)
    setup_logging(log_dir=str(tmp_path / "logs"))

    # ------------------------------------------------------------------
    # 1. Register RoE + init engagement folder (so raw/ exists)
    # ------------------------------------------------------------------
    roe = RulesOfEngagement.model_validate_yaml(sandbox_roe_yaml)
    engagement_id = "test-pipeline-001"
    register_roe(engagement_id, roe)
    init_engagement_folder(engagement_id, "10.10.10.5", "test")

    # ------------------------------------------------------------------
    # 2. Mock the LLM to return our fixture plan
    # ------------------------------------------------------------------
    plan_json = (fixtures_dir / "llm_responses" / "recon_plan_lame.json").read_text()
    mock_response = MagicMock()
    mock_response.content = plan_json

    # ------------------------------------------------------------------
    # 3. Mock run_subprocess to return fixture data based on the command
    # ------------------------------------------------------------------
    nmap_xml = (fixtures_dir / "nmap_lame_quick.xml").read_text()
    naabu_jsonl = (fixtures_dir / "naabu_lame.jsonl").read_text()
    httpx_json = (fixtures_dir / "httpx_lame.json").read_text()
    nuclei_jsonl = (fixtures_dir / "nuclei_lame.jsonl").read_text()
    feroxbuster_json = (fixtures_dir / "feroxbuster_lame.json").read_text()
    dnsx_json = (fixtures_dir / "dnsx_lame.json").read_text()

    from autored.subprocess_runner import SubprocessResult

    async def mock_run_subprocess(cmd, timeout=600):
        cmd_str = " ".join(cmd)
        if "nmap" in cmd_str:
            return SubprocessResult(
                stdout=nmap_xml, stderr="", returncode=0,
                duration_sec=5.0, command=cmd_str,
            )
        if "naabu" in cmd_str:
            return SubprocessResult(
                stdout=naabu_jsonl, stderr="", returncode=0,
                duration_sec=2.0, command=cmd_str,
            )
        if "httpx" in cmd_str:
            return SubprocessResult(
                stdout=httpx_json, stderr="", returncode=0,
                duration_sec=1.0, command=cmd_str,
            )
        if "nuclei" in cmd_str:
            return SubprocessResult(
                stdout=nuclei_jsonl, stderr="", returncode=0,
                duration_sec=10.0, command=cmd_str,
            )
        if "feroxbuster" in cmd_str:
            return SubprocessResult(
                stdout=feroxbuster_json, stderr="", returncode=0,
                duration_sec=15.0, command=cmd_str,
            )
        if "dnsx" in cmd_str:
            return SubprocessResult(
                stdout=dnsx_json, stderr="", returncode=0,
                duration_sec=1.0, command=cmd_str,
            )
        return SubprocessResult(
            stdout="", stderr="", returncode=1,
            duration_sec=0.1, command=cmd_str,
        )

    # ------------------------------------------------------------------
    # 4. Build initial state
    # ------------------------------------------------------------------
    state = EngagementState(
        engagement_id=engagement_id,
        target_scope=["10.10.10.5"],
        operator="test",
        rules_of_engagement=roe,
    )

    # ------------------------------------------------------------------
    # 5. Build graph + run with mocks in place
    #
    # We patch ``run_subprocess`` on every tool module that imports it
    # (each tool does ``from autored.subprocess_runner import run_subprocess``
    # which binds the original function into the tool module's namespace at
    # import time — patching the source module alone is insufficient once
    # the tool modules have already been imported by another test).
    # ------------------------------------------------------------------
    tool_modules = [
        "autored.tools.nmap",
        "autored.tools.naabu",
        "autored.tools.httpx_tool",
        "autored.tools.nuclei",
        "autored.tools.feroxbuster",
        "autored.tools.dnsx",
        "autored.tools.subfinder",
        "autored.tools.amass",
        "autored.tools.gobuster_vhost",
    ]

    checkpointer = await make_checkpointer(engagement_id)
    try:
        graph = build_phase1_graph(checkpointer)
        config = {"configurable": {"thread_id": engagement_id}}

        with patch("autored.agents.recon.get_model") as mock_get_model:
            mock_model = MagicMock()
            mock_model.ainvoke = AsyncMock(return_value=mock_response)
            mock_get_model.return_value = mock_model

            # Patch ``run_subprocess`` on every tool module that imports it.
            patchers = [
                patch(f"{mod}.run_subprocess", new=mock_run_subprocess)
                for mod in tool_modules
            ]
            for p in patchers:
                p.start()
            try:
                final_state = await graph.ainvoke(state, config=config)
            finally:
                for p in patchers:
                    p.stop()
    finally:
        # AsyncSqliteSaver holds an open aiosqlite connection — close it
        # so pytest-asyncio's event loop tears down cleanly.
        conn = getattr(checkpointer, "conn", None)
        if conn is not None:
            await conn.close()

    # ------------------------------------------------------------------
    # 6. Verify final state
    # ------------------------------------------------------------------
    # ``graph.ainvoke`` returns a state-shaped dict (LangGraph's default
    # behaviour for our StateGraph(EngagementState) setup).
    assert isinstance(final_state, dict)
    assert final_state["phase"] == "done"  # went through report_phase1 stub

    hosts = final_state["hosts"]
    assert len(hosts) >= 1
    assert any(h.ip == "10.10.10.5" for h in hosts)

    services = final_state["services"]
    assert len(services) >= 2  # at least ftp + ssh

    # ------------------------------------------------------------------
    # 7. Verify raw outputs were saved to engagements/<id>/raw/
    # ------------------------------------------------------------------
    raw_dir = tmp_path / "engagements" / engagement_id / "raw"
    assert raw_dir.exists(), f"raw dir not found at {raw_dir}"
    out_files = list(raw_dir.glob("*.out"))
    assert len(out_files) >= 1, f"no .out files in {raw_dir}"
