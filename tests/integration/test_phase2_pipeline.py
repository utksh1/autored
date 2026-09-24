"""Phase 2, Task 12 — Integration test: full Phase 2 pipeline, mocked.

End-to-end test that mocks the LLM router (``call_with_fallback`` for both
recon planning and vuln synthesis), ``run_subprocess`` in every recon tool
module, ``httpx.AsyncClient`` in the NVD tool, and ``ChromaStore`` at the
Vuln Agent's import site, then runs the full Phase 2 graph
(``build_phase2_graph``) against the Lame + Shocker fixtures from
Batches A-C.

Verifies the full Phase 2 chain runs as a single unit:

1. ``roe_gate_start`` registers (or re-confirms) the RoE.
2. ``recon_node`` → ``call_with_fallback("plan_recon", prompt)`` → mocked
   to return ``recon_plan_lame.json`` (3 steps: portscan, webenum, dnsenum).
3. The plan dispatches ``portscan_subagent`` (naabu + nmap),
   ``webenum_subagent`` (httpx + feroxbuster + nuclei) and
   ``dnsenum_subagent`` (dnsx) — each tool wrapper's
   ``run_subprocess`` call is mocked to return the matching fixture file
   (``nmap_lame_quick.xml``, ``naabu_lame.jsonl``, etc.).
4. ``recon_node`` merges the sub-agent outputs back into state shape
   (``hosts``, ``services``, ``web_apps``, ``subdomains``,
   ``directories``) and advances ``phase`` to ``"vuln"``.
5. ``vuln_node`` runs:
   - ``cvematcher_subagent`` queries NVD (mocked to return
     ``{"vulnerabilities": []}`` empty) → 0 CVE matches.
   - ``exploitfinder_subagent`` is skipped because no CVE matches were
     produced (the vuln node's ``unique_queries`` set is empty).
   - ``ChromaStore.query_similar_findings`` is mocked to return ``[]``.
   - ``call_with_fallback("synthesize_findings", prompt)`` → mocked to
     return ``vuln_hypotheses_shocker.json`` (Shellshock hypothesis).
   - ``hypothesiscritic_subagent`` queries DeepSeek via
     ``get_model("second_opinion")`` (mocked to return
     ``vuln_critique_shocker.json`` content) → verdict "sound" → self-
     critique loop converges after 1 iteration.
6. The constant conditional edge routes ``vuln → report_phase1`` (Phase 2
   always routes here per T10's graph wiring).
7. ``report_phase1`` sets ``phase = "done"``.

Asserts the final state has:
- ``phase == "done"`` (the report stub ran)
- at least 1 host (the nmap fixture has the Lame host)
- at least 1 service (the nmap fixture has 5 open ports)
- ``len(attack_hypotheses) >= 0`` — the brief explicitly uses ``>= 0``
  because the test verifies the pipeline runs end-to-end, not that
  hypotheses are produced. In practice the LLM mock returns 1 hypothesis
  (Shellshock), so this assertion is a tautology here — but it documents
  the intent and stays resilient if the LLM mock is later swapped for a
  parse-failing one.

Implementation notes
--------------------
- Recon-side mocking follows the T28 pattern (per-tool-module
  ``run_subprocess`` patch — patching ``autored.subprocess_runner.run_subprocess``
  alone does NOT intercept calls dispatched through the tool wrappers because
  each tool module binds the name at import time).
- Vuln-side mocking follows the T9 pattern with one key difference: T9
  mocks the 3 sub-agents entirely (``cvematcher_subagent``,
  ``exploitfinder_subagent``, ``hypothesiscritic_subagent``). Here we let
  them run for real and mock the underlying tool calls instead (NVD httpx,
  searchsploit subprocess via the per-tool-module ``run_subprocess``
  patch, Chroma, LLM) — exercising more of the integration surface, as
  the brief specifies.
- The hypothesiscritic subagent uses ``get_model("second_opinion")``
  directly (NOT ``call_with_fallback``), so we mock
  ``autored.subagents.hypothesiscritic.get_model`` to return a
  ``MagicMock`` whose ``.ainvoke`` returns a response with ``.content``
  set to the critique fixture JSON.
- The vuln agent's ``call_with_fallback`` is called once (initial
  synthesis). Revision is NOT called because the critique fixture says
  "sound" → loop converges after 1 iteration.
- NVD mock returns ``{"vulnerabilities": []}`` (empty) so cvematcher
  yields 0 CVE matches — vuln_node proceeds with no NVD-derived CVEs but
  still produces hypotheses from the LLM mock. This is the brief's
  explicit intent: "the test verifies the pipeline runs, not that
  hypotheses are produced".
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from autored.config import load_roe
from autored.graph import build_phase2_graph
from autored.logging import setup_logging
from autored.persistence.filesystem import init_engagement_folder
from autored.persistence.sqlite_saver import make_checkpointer
from autored.roe_guard import register_roe
from autored.state import EngagementState
from autored.subprocess_runner import SubprocessResult


@pytest.mark.asyncio
async def test_phase2_pipeline_mocked(tmp_path, monkeypatch, sandbox_roe_yaml, fixtures_dir):
    # Run inside tmp_path so engagements/ + logs/ never touch the repo.
    monkeypatch.chdir(tmp_path)
    setup_logging(log_dir=str(tmp_path / "logs"))

    # --- Register RoE ---------------------------------------------------
    roe = load_roe(sandbox_roe_yaml)
    engagement_id = "test-pipeline-002"
    register_roe(engagement_id, roe)
    init_engagement_folder(engagement_id, "10.10.10.56", "test")

    # --- Fixture payloads -----------------------------------------------
    plan_json = (fixtures_dir / "llm_responses" / "recon_plan_lame.json").read_text()
    hypotheses_json = (fixtures_dir / "llm_responses" / "vuln_hypotheses_shocker.json").read_text()
    critique_json = (fixtures_dir / "llm_responses" / "vuln_critique_shocker.json").read_text()
    nmap_xml = (fixtures_dir / "nmap_lame_quick.xml").read_text()
    naabu_jsonl = (fixtures_dir / "naabu_lame.jsonl").read_text()
    httpx_json = (fixtures_dir / "httpx_lame.json").read_text()
    nuclei_jsonl = (fixtures_dir / "nuclei_lame.jsonl").read_text()
    feroxbuster_json = (fixtures_dir / "feroxbuster_lame.json").read_text()
    dnsx_json = (fixtures_dir / "dnsx_lame.json").read_text()
    searchsploit_json = (fixtures_dir / "searchsploit_nginx.json").read_text()

    # --- Mock run_subprocess per tool module (T28 pattern) -------------
    # Each tool module binds `run_subprocess` at import time, so we patch
    # the binding in every Phase 1 + Phase 2 (searchsploit) tool module.
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
            stdout = "[]"  # not in fixture plan; empty fallback
        elif "amass" in cmd_str:
            stdout = "[]"
        elif "dnsx" in cmd_str:
            stdout = dnsx_json
        elif "gobuster" in cmd_str:
            stdout = ""
        elif "searchsploit" in cmd_str:
            stdout = searchsploit_json
        else:
            stdout = ""
        return SubprocessResult(
            stdout=stdout,
            stderr="",
            returncode=0,
            duration_sec=1.0,
            command=cmd_str,
        )

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
        "autored.tools.searchsploit",
    ]

    # --- Mock NVD httpx.AsyncClient → empty vulnerabilities ---------------
    # cvematcher_subagent → nvd_query → httpx.AsyncClient(timeout=30). We
    # patch the class so `async with httpx.AsyncClient(...) as client:`
    # yields our mock client whose .get() returns the empty NVD response.
    mock_httpx_response = MagicMock()
    mock_httpx_response.status_code = 200
    mock_httpx_response.json.return_value = {"vulnerabilities": []}
    mock_httpx_response.raise_for_status = MagicMock()
    mock_httpx_client = AsyncMock()
    mock_httpx_client.__aenter__ = AsyncMock(return_value=mock_httpx_client)
    mock_httpx_client.__aexit__ = AsyncMock(return_value=None)
    mock_httpx_client.get = AsyncMock(return_value=mock_httpx_response)

    # --- Mock Chroma ----------------------------------------------------
    mock_chroma = MagicMock()
    mock_chroma.query_similar_findings = AsyncMock(return_value=[])

    # --- Mock DeepSeek second-opinion model used by hypothesiscritic ---
    # The hypothesiscritic subagent uses `get_model("second_opinion")`
    # directly (NOT call_with_fallback). The returned model is `await
    # model.ainvoke(prompt)` → response with `.content` set to the
    # critique fixture JSON. The fixture says verdict "sound" so the
    # self-critique loop converges after 1 iteration.
    mock_critic_response = MagicMock()
    mock_critic_response.content = critique_json
    mock_critic_model = MagicMock()
    mock_critic_model.ainvoke = AsyncMock(return_value=mock_critic_response)

    # --- Build initial state --------------------------------------------
    state = EngagementState(
        engagement_id=engagement_id,
        target_scope=["10.10.10.56"],
        operator="test",
        rules_of_engagement=roe,
    )

    # --- Patch run_subprocess in every tool module ----------------------
    patchers = [patch(m + ".run_subprocess", side_effect=mock_run_subprocess) for m in tool_modules]
    for p in patchers:
        p.start()
    try:
        with (
            # Recon planner LLM
            patch(
                "autored.agents.recon.call_with_fallback",
                new=AsyncMock(return_value=plan_json),
            ),
            # Vuln synthesis LLM (also called for revision, but revision
            # won't trigger because the critique fixture says "sound")
            patch(
                "autored.agents.vuln.call_with_fallback",
                new=AsyncMock(return_value=hypotheses_json),
            ),
            # DeepSeek second-opinion model used by hypothesiscritic
            patch(
                "autored.subagents.hypothesiscritic.get_model",
                return_value=mock_critic_model,
            ),
            # NVD httpx client (cvematcher's underlying tool)
            patch(
                "autored.tools.nvd.httpx.AsyncClient",
                return_value=mock_httpx_client,
            ),
            # Chroma cross-engagement memory
            patch(
                "autored.agents.vuln.ChromaStore",
                return_value=mock_chroma,
            ),
        ):
            # --- Build and run graph --------------------------------
            checkpointer = await make_checkpointer(engagement_id)
            graph = build_phase2_graph(checkpointer)
            config = {"configurable": {"thread_id": engagement_id}}
            try:
                final_state = await graph.ainvoke(state, config=config)
            finally:
                if hasattr(checkpointer, "conn"):
                    await checkpointer.conn.close()
    finally:
        for p in patchers:
            p.stop()

    # --- Verify final state ---------------------------------------------
    assert final_state["phase"] == "done"  # went through report_phase1 stub
    assert len(final_state["hosts"]) >= 1
    assert len(final_state["services"]) >= 1
    # Vuln Agent should have produced hypotheses from the LLM mock.
    # The brief explicitly uses >= 0 — the test verifies the pipeline runs
    # end-to-end, not that hypotheses are produced. In practice the LLM
    # mock returns 1 hypothesis (Shellshock), so this is >= 1 in practice.
    assert len(final_state["attack_hypotheses"]) >= 0
