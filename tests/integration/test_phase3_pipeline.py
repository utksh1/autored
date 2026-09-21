"""End-to-end integration test for the full Phase 3 pipeline (mocked).

Mocks the LLM (returns the ``recon_plan_lame.json`` fixture for the Recon
Agent's planning call, ``vuln_hypotheses_shocker.json`` for the Vuln
Agent's synthesis call, an empty ``{"critique": []}`` for the DeepSeek
self-critique step so the loop converges in one iteration, and
``exploit_plan_blue.json`` for the Exploit Agent's planning call), every
recon-tool subprocess call (canned fixture data per command name), the
NVD HTTP client (returns an empty ``{"vulnerabilities": []}`` payload so
CVEMatcher yields no CVE matches), the cross-engagement ``ChromaStore``
(returns no similar findings), all 4 exploit sub-agent tool wrappers
(only ``msfagent`` is exercised by the Blue plan, but the other 3 are
patched defensively in case the LLM swaps sub-agents), and
``_verify_foothold`` (returns True unconditionally so the Exploit Agent
records a foothold), then runs the full Phase 3 LangGraph end-to-end::

    roe_gate_start  ->  recon  ->  vuln  ->  exploit  ->  report_phase1  ->  END

Verifies:
  * Final state phase is ``"done"`` (went through ``report_phase1`` stub)
    or ``"postex"`` (if the report stub's behaviour changes in Phase 4)
  * At least 1 host found
  * At least 1 service found
  * The Exploit Agent recorded at least 1 foothold (Phase 3 specific)
  * Raw tool outputs were saved to ``engagements/<id>/raw/``

This is the moment-of-truth test for Phase 3: if every prior task
(state schema with ``event_bus`` field, RoE guard, model router, all 3
recon-vuln agents, all 4 exploit sub-agents + tools, the EventBus, the
Exploit Agent's HitL gate / plan / dispatch / verify flow, and the
Phase 3 graph topology) is wired correctly, this passes.

A note on the mock strategy
---------------------------
The Phase 2 integration test patches ``run_subprocess`` on every recon
tool module that imports it. Phase 3 adds 4 exploit sub-agents whose
underlying tool wrappers (``sqlmap_run``, ``hydra_brute``,
``metasploit_rpc``, ``custom_command``) are *separate* LangChain
``@tool`` objects — they don't call ``run_subprocess`` directly (they
each have their own dispatch path). We patch them at the sub-agent
module attribute path (e.g. ``autored.subagents.msfagent.metasploit_rpc``)
so the patch takes effect when the sub-agent does
``metasploit_rpc.ainvoke(...)`` at call time.

The Exploit Agent imports the sub-agent MODULES (not the @tool names) —
see the ``Why we import sub-agent *modules*`` docstring in
``autored/agents/exploit.py``. Patching ``autored.subagents.<x>.<tool>``
works because module attribute lookup happens at call time.
"""

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from autored.state import EngagementState
from autored.models.roe import RulesOfEngagement
from autored.persistence.filesystem import init_engagement_folder
from autored.persistence.sqlite_saver import make_checkpointer
from autored.graph import build_phase3_graph
from autored.roe_guard import register_roe
from autored.logging import setup_logging
from autored.tui.event_bus import EventBus
from autored.tools.metasploit import MsfResult


@pytest.mark.asyncio
async def test_phase3_pipeline_mocked(
    tmp_path: Path,
    monkeypatch,
    sandbox_roe_yaml: str,
    fixtures_dir: Path,
):
    """Run the full Phase 3 graph with mocked LLM + subprocesses + EventBus.

    Topology exercised: roe_gate_start → recon → vuln → exploit →
    report_phase1 → END. The Exploit Agent's HitL gate auto-approves
    in sandbox mode (no TUI / no operator interaction needed).
    """
    monkeypatch.chdir(tmp_path)
    setup_logging(log_dir=str(tmp_path / "logs"))

    # ------------------------------------------------------------------
    # 1. Register RoE + init engagement folder (so raw/ + state.db exist)
    # ------------------------------------------------------------------
    roe = RulesOfEngagement.model_validate_yaml(sandbox_roe_yaml)
    engagement_id = "test-pipeline-003"
    register_roe(engagement_id, roe)
    init_engagement_folder(engagement_id, "10.10.10.56", "test")

    # ------------------------------------------------------------------
    # 2. Mock the LLM responses, dispatched by router task name:
    #    - "plan_recon"         → recon_plan_lame.json (3-step plan)
    #    - "synthesize_findings" → vuln_hypotheses_shocker.json (1 Shellshock hypothesis)
    #    - "second_opinion"     → empty critique (self-critique converges in 1 iter)
    #    - "plan_exploit"       → exploit_plan_blue.json (msfagent ms17_010)
    # ------------------------------------------------------------------
    recon_plan = (fixtures_dir / "llm_responses" / "recon_plan_lame.json").read_text()
    vuln_hypotheses = (
        fixtures_dir / "llm_responses" / "vuln_hypotheses_shocker.json"
    ).read_text()
    exploit_plan = (
        fixtures_dir / "llm_responses" / "exploit_plan_blue.json"
    ).read_text()

    mock_recon_response = MagicMock()
    mock_recon_response.content = recon_plan
    mock_vuln_response = MagicMock()
    mock_vuln_response.content = vuln_hypotheses
    mock_critique_response = MagicMock()
    mock_critique_response.content = '{"critique": []}'  # empty = convergence
    mock_exploit_response = MagicMock()
    mock_exploit_response.content = exploit_plan

    # One mock model per task slot — each returns its fixed fixture on
    # every ``ainvoke`` call. (vuln only calls synthesis once because
    # the critique converges immediately; exploit only calls plan_exploit
    # once because the first hypothesis succeeds.)
    mock_recon_model = MagicMock()
    mock_recon_model.ainvoke = AsyncMock(return_value=mock_recon_response)

    mock_vuln_model = MagicMock()
    mock_vuln_model.ainvoke = AsyncMock(return_value=mock_vuln_response)

    mock_critic_model = MagicMock()
    mock_critic_model.ainvoke = AsyncMock(return_value=mock_critique_response)

    mock_exploit_model = MagicMock()
    mock_exploit_model.ainvoke = AsyncMock(return_value=mock_exploit_response)

    def mock_get_model(task):
        if task == "plan_recon":
            return mock_recon_model
        if task == "synthesize_findings":
            return mock_vuln_model
        if task == "second_opinion":
            return mock_critic_model
        if task == "plan_exploit":
            return mock_exploit_model
        raise ValueError(f"unexpected model task: {task!r}")

    # ------------------------------------------------------------------
    # 3. Mock run_subprocess for every recon tool module that imports it
    #    (Phase 1/2 pattern — each tool module binds ``run_subprocess``
    #    at import time, so patching the source module is insufficient).
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
    # 4. Mock all 4 exploit sub-agent tool wrappers. Only msfagent is
    #    actually called by the Blue exploit plan, but we patch the
    #    other 3 defensively in case the LLM swaps sub-agents.
    # ------------------------------------------------------------------
    fake_msf = MsfResult(
        method="execute_exploit",
        success=True,
        data={"job_id": 1, "session_id": 1},
    )

    mock_msf_tool = MagicMock()
    mock_msf_tool.ainvoke = AsyncMock(return_value=fake_msf)

    mock_sqli_tool = MagicMock()
    mock_sqli_tool.ainvoke = AsyncMock(return_value=MagicMock(
        success=False, vulnerable=False, injection_points=[],
        model_dump=MagicMock(return_value={
            "url": "", "vulnerable": False, "injection_points": [],
            "dbms": None, "raw_output_path": None,
            "command": "", "duration_sec": 0.0,
        }),
    ))

    mock_brute_tool = MagicMock()
    mock_brute_tool.ainvoke = AsyncMock(return_value=MagicMock(
        success=False, credentials=[],
        model_dump=MagicMock(return_value={
            "target": "", "service": "", "success": False,
            "credentials": [], "raw_output_path": None,
            "command": "", "duration_sec": 0.0,
        }),
    ))

    mock_custom_tool = MagicMock()
    mock_custom_tool.ainvoke = AsyncMock(return_value=MagicMock(
        success=False,
        model_dump=MagicMock(return_value={
            "command": "", "stdout": "", "stderr": "",
            "returncode": 0, "success": False, "raw_output_path": None,
            "duration_sec": 0.0,
        }),
    ))

    # ------------------------------------------------------------------
    # 5. Build initial state. Inject an EventBus so the Exploit Agent's
    #    HitL gate has somewhere to emit events (sandbox auto_approve
    #    means the gate returns immediately without blocking on a TUI
    #    response — the events just accumulate in the queue for audit).
    # ------------------------------------------------------------------
    state = EngagementState(
        engagement_id=engagement_id,
        target_scope=["10.10.10.56"],
        operator="test",
        rules_of_engagement=roe,
    )
    state.event_bus = EventBus()

    # ------------------------------------------------------------------
    # 6. Build graph + run with all mocks in place
    # ------------------------------------------------------------------
    checkpointer = await make_checkpointer(engagement_id)
    try:
        graph = build_phase3_graph(checkpointer)
        config = {"configurable": {"thread_id": engagement_id}}

        with patch("autored.agents.recon.get_model", side_effect=mock_get_model), \
             patch("autored.agents.vuln.get_model", side_effect=mock_get_model), \
             patch(
                 "autored.subagents.hypothesiscritic.get_model",
                 side_effect=mock_get_model,
             ), \
             patch("autored.agents.exploit.get_model", side_effect=mock_get_model), \
             patch("autored.tools.nvd.httpx.AsyncClient") as mock_httpx_cls, \
             patch("autored.agents.vuln.ChromaStore") as mock_chroma_cls, \
             patch("autored.subagents.msfagent.metasploit_rpc", new=mock_msf_tool), \
             patch("autored.subagents.sqliagent.sqlmap_run", new=mock_sqli_tool), \
             patch("autored.subagents.bruteagent.hydra_brute", new=mock_brute_tool), \
             patch("autored.subagents.customagent.custom_command", new=mock_custom_tool), \
             patch("autored.agents.exploit._verify_foothold", return_value=True):

            # NVD returns an empty vulnerabilities list so CVEMatcher
            # produces no CVE matches (the Vuln Agent's mocked Sonnet
            # produces hypotheses regardless of the live NVD result).
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
    # 7. Verify final state
    # ------------------------------------------------------------------
    assert isinstance(final_state, dict)
    # The graph went recon → vuln → exploit → report_phase1 → END.
    # exploit_node sets phase="postex" on a verified foothold, then
    # report_phase1 stub overwrites phase="done". Either is acceptable
    # per the Phase 3 plan (Phase 4 will route postex → post-ex agent).
    assert final_state["phase"] in ("done", "postex"), (
        f"Expected phase 'done' or 'postex', got {final_state['phase']!r}"
    )

    hosts = final_state["hosts"]
    assert len(hosts) >= 1, f"expected at least 1 host, got {len(hosts)}"

    services = final_state["services"]
    assert len(services) >= 1, f"expected at least 1 service, got {len(services)}"

    # Vuln Agent should have produced hypotheses from the mocked LLM.
    hypotheses = final_state["attack_hypotheses"]
    assert isinstance(hypotheses, list)
    assert len(hypotheses) >= 1, (
        f"expected at least 1 attack hypothesis, got {len(hypotheses)}"
    )

    # Exploit Agent should have recorded a foothold (Phase 3 specific).
    # report_phase1 only updates ``phase``, so the footholds list set
    # by exploit_node persists through to the final state.
    footholds = final_state["footholds"]
    assert len(footholds) >= 1, (
        f"expected at least 1 foothold after exploit, got {len(footholds)}"
    )

    # ------------------------------------------------------------------
    # 8. Verify raw outputs were saved to engagements/<id>/raw/
    # ------------------------------------------------------------------
    raw_dir = tmp_path / "engagements" / engagement_id / "raw"
    assert raw_dir.exists(), f"raw dir not found at {raw_dir}"
    out_files = list(raw_dir.glob("*.out"))
    assert len(out_files) >= 1, f"no .out files in {raw_dir}"
