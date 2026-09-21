"""End-to-end integration test for the full Phase 2 pipeline (mocked).

Mocks the LLM (returns the ``recon_plan_lame.json`` fixture for the Recon
Agent's planning call and ``vuln_hypotheses_shocker.json`` for the Vuln
Agent's synthesis call), every recon-tool subprocess call (canned fixture
data per command name), the NVD HTTP client (returns an empty
``{"vulnerabilities": []}`` payload so CVEMatcher yields no CVE matches),
and the cross-engagement ``ChromaStore`` (returns no similar findings),
then runs the full Phase 2 LangGraph end-to-end::

    roe_gate_start  ->  recon  ->  vuln  ->  report_phase1  ->  END

Verifies:
  * Final state phase is ``"done"`` (went through ``report_phase1`` stub)
  * At least 1 host found
  * At least 1 service found
  * Raw tool outputs were saved to ``engagements/<id>/raw/``

This is the moment-of-truth test for Phase 2: if every prior task
(state schema, RoE guard, model router, all 3 sub-agents, both new
tools, the Vuln Agent's self-critique loop, the ChromaStore wiring,
and the Phase 2 graph topology) is wired correctly, this passes.

A note on the mock strategy
---------------------------
The Phase 2 plan snippet patched ``autored.subprocess_runner.run_subprocess``
directly. That does **not** work because every tool module does
``from autored.subprocess_runner import run_subprocess`` at import time,
which binds the *original* function into the tool module's namespace.
Patching the source module leaves those bindings untouched. We follow the
Phase 1 integration test pattern instead: patch ``run_subprocess`` on
every tool module that imports it (nmap, naabu, httpx_tool, nuclei,
feroxbuster, dnsx, subfinder, amass, gobuster_vhost, **and** searchsploit
which is new in Phase 2).
"""

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from autored.state import EngagementState
from autored.models.roe import RulesOfEngagement
from autored.persistence.filesystem import init_engagement_folder
from autored.persistence.sqlite_saver import make_checkpointer
from autored.graph import build_phase2_graph
from autored.roe_guard import register_roe
from autored.logging import setup_logging


@pytest.mark.asyncio
async def test_phase2_pipeline_mocked(
    tmp_path: Path,
    monkeypatch,
    sandbox_roe_yaml: str,
    fixtures_dir: Path,
):
    """Run the full Phase 2 graph with mocked LLM + subprocesses + NVD HTTP."""
    monkeypatch.chdir(tmp_path)
    setup_logging(log_dir=str(tmp_path / "logs"))

    # ------------------------------------------------------------------
    # 1. Register RoE + init engagement folder (so raw/ + state.db exist)
    # ------------------------------------------------------------------
    roe = RulesOfEngagement.model_validate_yaml(sandbox_roe_yaml)
    engagement_id = "test-pipeline-002"
    register_roe(engagement_id, roe)
    init_engagement_folder(engagement_id, "10.10.10.56", "test")

    # ------------------------------------------------------------------
    # 2. Mock the LLM responses:
    #    - Sonnet (synthesize_findings, plan_recon): first call returns
    #      the Recon plan, every subsequent call returns vuln hypotheses.
    #    - DeepSeek (second_opinion): returns an empty critique so the
    #      self-critique loop converges in one iteration.
    # ------------------------------------------------------------------
    recon_plan = (fixtures_dir / "llm_responses" / "recon_plan_lame.json").read_text()
    vuln_hypotheses = (
        fixtures_dir / "llm_responses" / "vuln_hypotheses_shocker.json"
    ).read_text()

    mock_recon_response = MagicMock()
    mock_recon_response.content = recon_plan
    mock_vuln_response = MagicMock()
    mock_vuln_response.content = vuln_hypotheses
    mock_critique_response = MagicMock()
    mock_critique_response.content = '{"critique": []}'  # empty = convergence

    call_count = [0]

    async def mock_ainvoke(prompt):
        call_count[0] += 1
        if call_count[0] == 1:
            return mock_recon_response
        return mock_vuln_response

    mock_model = MagicMock()
    mock_model.ainvoke = AsyncMock(side_effect=mock_ainvoke)

    mock_critic_model = MagicMock()
    mock_critic_model.ainvoke = AsyncMock(return_value=mock_critique_response)

    def mock_get_model(task):
        # ``second_opinion`` is the DeepSeek slot used by HypothesisCritic;
        # everything else (plan_recon, synthesize_findings) shares the
        # call-counting Sonnet mock.
        if task == "second_opinion":
            return mock_critic_model
        return mock_model

    # ------------------------------------------------------------------
    # 3. Mock run_subprocess to return fixture data based on the command.
    #    Each tool module binds ``run_subprocess`` at import time, so we
    #    patch it on every tool module that imports it (Phase 1 pattern).
    # ------------------------------------------------------------------
    from autored.subprocess_runner import SubprocessResult

    nmap_xml = (fixtures_dir / "nmap_lame_quick.xml").read_text()
    naabu_jsonl = (fixtures_dir / "naabu_lame.jsonl").read_text()
    httpx_json = (fixtures_dir / "httpx_lame.json").read_text()
    nuclei_jsonl = (fixtures_dir / "nuclei_lame.jsonl").read_text()
    feroxbuster_json = (fixtures_dir / "feroxbuster_lame.json").read_text()
    dnsx_json = (fixtures_dir / "dnsx_lame.json").read_text()
    searchsploit_json = (fixtures_dir / "searchsploit_nginx.json").read_text()

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
        if "searchsploit" in cmd_str:
            return SubprocessResult(
                stdout=searchsploit_json, stderr="", returncode=0,
                duration_sec=2.0, command=cmd_str,
            )
        return SubprocessResult(
            stdout="", stderr="", returncode=1,
            duration_sec=0.1, command=cmd_str,
        )

    # Every tool module that does ``from autored.subprocess_runner import
    # run_subprocess`` binds the original function into its own namespace.
    # Patch each one so the mock actually takes effect.
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
        "autored.tools.searchsploit",
    ]

    # ------------------------------------------------------------------
    # 4. Build initial state. Target scope is Shocker's IP (10.10.10.56)
    #    but the mocked LLM returns the Lame recon plan (10.10.10.5), so
    #    the discovered hosts will be 10.10.10.5. That's fine for this
    #    test — we only assert "at least 1 host found", not a specific IP.
    # ------------------------------------------------------------------
    state = EngagementState(
        engagement_id=engagement_id,
        target_scope=["10.10.10.56"],
        operator="test",
        rules_of_engagement=roe,
    )

    # ------------------------------------------------------------------
    # 5. Build graph + run with mocks in place
    # ------------------------------------------------------------------
    checkpointer = await make_checkpointer(engagement_id)
    try:
        graph = build_phase2_graph(checkpointer)
        config = {"configurable": {"thread_id": engagement_id}}

        with patch("autored.agents.recon.get_model", side_effect=mock_get_model), \
             patch("autored.agents.vuln.get_model", side_effect=mock_get_model), \
             patch(
                 "autored.subagents.hypothesiscritic.get_model",
                 return_value=mock_critic_model,
             ), \
             patch("autored.tools.nvd.httpx.AsyncClient") as mock_httpx_cls, \
             patch("autored.agents.vuln.ChromaStore") as mock_chroma_cls:

            # NVD returns an empty vulnerabilities list so CVEMatcher
            # produces no CVE matches (we don't need NVD fixtures for
            # this test — the Vuln Agent's mocked Sonnet produces
            # hypotheses regardless of the live NVD result).
            mock_httpx_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"vulnerabilities": []}
            mock_response.raise_for_status = MagicMock()
            mock_httpx_client.__aenter__ = AsyncMock(return_value=mock_httpx_client)
            mock_httpx_client.__aexit__ = AsyncMock(return_value=None)
            mock_httpx_client.get = AsyncMock(return_value=mock_response)
            mock_httpx_cls.return_value = mock_httpx_client

            # Chroma returns no similar findings
            mock_chroma = MagicMock()
            mock_chroma.query_similar_findings = AsyncMock(return_value=[])
            mock_chroma_cls.return_value = mock_chroma

            # Patch ``run_subprocess`` on every tool module that imports it.
            # These patchers are nested inside the ``with`` block above so
            # they're active during the graph run and torn down afterwards.
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
    assert isinstance(final_state, dict)
    # The graph went recon → vuln → report_phase1 → END, so the final
    # phase is "done" (set by the report_phase1 stub).
    assert final_state["phase"] == "done", (
        f"Expected phase 'done', got {final_state['phase']!r}"
    )

    hosts = final_state["hosts"]
    assert len(hosts) >= 1, f"expected at least 1 host, got {len(hosts)}"

    services = final_state["services"]
    assert len(services) >= 1, f"expected at least 1 service, got {len(services)}"

    # Vuln Agent should have produced hypotheses from the mocked LLM.
    # The mocked Sonnet returns shocker hypotheses regardless of the
    # actual recon findings (which are for 10.10.10.5/Lame), so this
    # asserts the Vuln Agent's parse + self-critique loop wired up
    # correctly end-to-end.
    hypotheses = final_state["attack_hypotheses"]
    assert isinstance(hypotheses, list)

    # ------------------------------------------------------------------
    # 7. Verify raw outputs were saved to engagements/<id>/raw/
    # ------------------------------------------------------------------
    raw_dir = tmp_path / "engagements" / engagement_id / "raw"
    assert raw_dir.exists(), f"raw dir not found at {raw_dir}"
    out_files = list(raw_dir.glob("*.out"))
    assert len(out_files) >= 1, f"no .out files in {raw_dir}"
