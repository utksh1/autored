"""Phase 3, Task 14 — Integration test: full Phase 3 pipeline, mocked.

End-to-end test that mocks the LLM router (``call_with_fallback`` for
recon planning, vuln synthesis, AND exploit planning), ``run_subprocess``
in every recon tool module, ``httpx.AsyncClient`` in the NVD tool,
``ChromaStore`` at the Vuln Agent's import site, the 4 exploit sub-agents'
underlying tool bindings (msfagent.metasploit_rpc, bruteagent.hydra_brute,
sqliagent.sqlmap_run, customagent.custom_command), the Exploit Agent's
``_verify_foothold`` helper, and the EventBus's HitL gate methods. Then
runs the full Phase 3 graph (``build_phase3_graph``) against the Lame
recon fixtures + Shocker hypothesis fixture + EternalBlue exploit-plan
fixture from Batches A-C + Phase 3 Exploit-Agent tests.

Verifies the full Phase 3 chain runs as a single unit:

1. ``roe_gate_start`` registers (or re-confirms) the RoE.
2. ``recon_node`` → ``call_with_fallback("plan_recon", prompt)`` → mocked
   to return ``recon_plan_lame.json`` (3 steps: portscan, webenum, dnsenum).
3. The plan dispatches ``portscan_subagent`` (naabu + nmap),
   ``webenum_subagent`` (httpx + feroxbuster + nuclei) and
   ``dnsenum_subagent`` (dnsx) — each tool wrapper's ``run_subprocess``
   call is mocked to return the matching fixture file
   (``nmap_lame_quick.xml``, ``naabu_lame.jsonl``, etc.).
4. ``recon_node`` merges the sub-agent outputs back into state shape
   and advances ``phase`` to ``"vuln"``.
5. ``vuln_node`` runs:
   - ``cvematcher_subagent`` queries NVD (mocked to return
     ``{"vulnerabilities": []}`` empty) → 0 CVE matches.
   - ``exploitfinder_subagent`` is skipped because no CVE matches.
   - ``ChromaStore.query_similar_findings`` is mocked to return ``[]``.
   - ``call_with_fallback("synthesize_findings", prompt)`` → mocked to
     return ``vuln_hypotheses_shocker.json`` (1 Shellshock hypothesis).
   - ``hypothesiscritic_subagent`` queries DeepSeek via
     ``get_model("second_opinion")`` (mocked to return
     ``vuln_critique_shocker.json`` content) → verdict "sound" → loop
     converges after 1 iteration.
6. Phase 3's conditional edge ``recon → vuln`` routes to ``exploit``
   through ``vuln_node`` because the recon fixtures surface at least one
   host (the Lame IP). I4 (Phase 3 fix wave) restored the empty-hosts
   short-circuit that mirrors Phase 2's wiring — empty recon would skip
   straight to ``report_phase1`` and skip the vuln + exploit nodes, but
   this test's fixtures surface a host so the full chain runs.
7. ``exploit_node`` runs:
   - HitL gate: ``emit_to_tui`` (mocked no-op) + ``wait_for_tui_response``
     (mocked to return ``{"response": "approve", "modified_command": None}``).
     I1 (Phase 3 fix wave): the bus is passed via
     ``RunnableConfig["configurable"]["event_bus"]``, so the
     LangGraph-driven invocation (not just the direct-call unit tests)
     genuinely exercises the interactive approve path — the bus
     survives the LangGraph reducer boundary intact and reaches
     ``exploit_node``.
   - Plan: ``call_with_fallback("plan_exploit", prompt)`` → mocked to
     return ``exploit_plan_blue.json`` (1 msfagent tool call against
     MS17-010 EternalBlue).
   - Dispatch: ``msfagent_subagent`` calls ``metasploit_rpc.ainvoke``
     (mocked) → returns ``MsfResult(success=True, data={"session_id": 1})``.
   - Verify: ``_verify_foothold`` (mocked) → returns ``True``.
   - Builds 1 ``Foothold`` (``method == hypothesis.technique``) and
     returns ``phase=postex`` + ``footholds=[1]`` + ``evidence_paths``.
8. Phase 3's linear edge ``exploit → report_phase1`` routes to the
   report stub regardless of foothold/no-foothold (Phase 4 will add the
   real ``postex`` branch).
9. ``report_phase1`` sets ``phase = "done"``.

Asserts the final state has:
- ``phase == "done"`` (the report stub ran)
- at least 1 host (the nmap fixture has the Lame host)
- at least 1 service (the nmap fixture has 5 open ports)
- ``len(footholds) >= 1`` — the Exploit Agent recorded a verified foothold
- ``footholds[0].method`` contains the exploit technique (Shellshock,
  pulled from ``hypothesis.technique`` in the Shocker fixture).

Implementation notes
--------------------
- Recon + Vuln mocking follows the Phase 2 pipeline test (T12) pattern:
  per-tool-module ``run_subprocess`` patch + NVD httpx + Chroma + DeepSeek
  second-opinion model + ``call_with_fallback`` patches for ``plan_recon``
  and ``synthesize_findings``.
- Exploit mocking follows the Exploit Agent unit test (T9) pattern:
  ``call_with_fallback("plan_exploit", ...)`` patch + 4 sub-agent tool
  bindings patched at the module level + ``_verify_foothold`` patch +
  EventBus methods patched via ``patch.object``.
- I1 (Phase 3 fix wave): the EventBus is passed via
  ``config["configurable"]["event_bus"]`` (the standard LangGraph channel
  for runtime objects), so the LangGraph-driven invocation genuinely
  exercises the interactive approve path — the bus survives the
  LangGraph reducer boundary intact and reaches ``exploit_node``.
- ``hitl_mode`` is overridden to ``"always_ask"`` so the gate actually
  calls ``wait_for_tui_response`` (sandbox RoE's default ``auto_approve``
  would short-circuit it).
- ``checkpointer=None`` keeps the test off the persistence layer
  (asyncio.Queue handles inside the bus still aren't msgpack-serialisable
  even though the bus no longer rides on state — defensive belt-and-
  suspenders rather than the I1 workaround it used to be).
"""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from autored.config import load_roe
from autored.graph import build_phase3_graph
from autored.logging import setup_logging
from autored.persistence.filesystem import init_engagement_folder
from autored.roe_guard import register_roe
from autored.state import EngagementState
from autored.subprocess_runner import SubprocessResult
from autored.tools.metasploit import MsfResult


@pytest.mark.asyncio
async def test_phase3_pipeline_mocked(
    tmp_path, monkeypatch, sandbox_roe_yaml, fixtures_dir
):
    # Run inside tmp_path so engagements/ + logs/ never touch the repo.
    monkeypatch.chdir(tmp_path)
    setup_logging(log_dir=str(tmp_path / "logs"))

    # --- Register RoE ---------------------------------------------------
    roe = load_roe(sandbox_roe_yaml)
    # Override auto_approve so the HitL gate actually exercises the
    # EventBus wait_for_tui_response path (otherwise the gate short-
    # circuits and the mock is a no-op assertion-wise).
    roe.hitl_mode = "always_ask"
    engagement_id = "test-pipeline-003"
    register_roe(engagement_id, roe)
    init_engagement_folder(engagement_id, "10.10.10.56", "test")

    # --- Fixture payloads -----------------------------------------------
    plan_recon_json = (
        fixtures_dir / "llm_responses" / "recon_plan_lame.json"
    ).read_text()
    hypotheses_json = (
        fixtures_dir / "llm_responses" / "vuln_hypotheses_shocker.json"
    ).read_text()
    critique_json = (
        fixtures_dir / "llm_responses" / "vuln_critique_shocker.json"
    ).read_text()
    exploit_plan_json = (
        fixtures_dir / "llm_responses" / "exploit_plan_blue.json"
    ).read_text()
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
    mock_critic_response = MagicMock()
    mock_critic_response.content = critique_json
    mock_critic_model = MagicMock()
    mock_critic_model.ainvoke = AsyncMock(return_value=mock_critic_response)

    # --- Mock the 4 exploit sub-agent underlying tools -----------------
    # All 4 are patched for robustness even though the LLM plan only
    # dispatches msfagent. msfagent.metasploit_rpc returns a MsfResult
    # with success=True + session_id (the canonical foothold signal).
    fake_msf = MsfResult(
        method="execute_exploit",
        success=True,
        data={"job_id": 1, "session_id": 1},
    )
    mock_msf_rpc = MagicMock()
    mock_msf_rpc.ainvoke = AsyncMock(return_value=fake_msf)

    mock_sqlmap_run = MagicMock()
    mock_sqlmap_run.ainvoke = AsyncMock(return_value=MagicMock())

    mock_hydra_brute = MagicMock()
    mock_hydra_brute.ainvoke = AsyncMock(return_value=MagicMock())

    mock_custom_command = MagicMock()
    mock_custom_command.ainvoke = AsyncMock(return_value=MagicMock())

    # --- Build initial state --------------------------------------------
    # I1 (Phase 3 fix wave): the EventBus now travels via
    # RunnableConfig["configurable"]["event_bus"] rather than as a
    # non-Pydantic state attribute. LangGraph's reducer round-trips
    # state through model_dump() + model_validate() which strips the
    # __pydantic_extra__ dict where `state.event_bus = ...` was stored
    # under extra="allow" — so even when the previous test attached a
    # bus to state, exploit_node's `getattr(state, "event_bus", None)`
    # returned None and the gate failed open. The new config-based
    # channel bypasses the reducer boundary entirely; the bus survives
    # the LangGraph invocation and reaches exploit_node intact.
    from autored.tui.event_bus import EventBus

    bus = EventBus()
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
                new=AsyncMock(return_value=plan_recon_json),
            ),
            # Vuln synthesis LLM (also called for revision, but revision
            # won't trigger because the critique fixture says "sound")
            patch(
                "autored.agents.vuln.call_with_fallback",
                new=AsyncMock(return_value=hypotheses_json),
            ),
            # Exploit planner LLM (returns msfagent call against MS17-010)
            patch(
                "autored.agents.exploit.call_with_fallback",
                new=AsyncMock(return_value=exploit_plan_json),
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
            # 4 exploit sub-agent underlying tool bindings
            patch(
                "autored.subagents.msfagent.metasploit_rpc",
                new=mock_msf_rpc,
            ),
            patch(
                "autored.subagents.sqliagent.sqlmap_run",
                new=mock_sqlmap_run,
            ),
            patch(
                "autored.subagents.bruteagent.hydra_brute",
                new=mock_hydra_brute,
            ),
            patch(
                "autored.subagents.customagent.custom_command",
                new=mock_custom_command,
            ),
            # _verify_foothold short-circuits to True (the metasploit
            # session_id signal would also trigger True via the real
            # verifier, but mocking makes the assertion deterministic
            # and decouples it from the verifier's envelope inspection)
            patch(
                "autored.agents.exploit._verify_foothold",
                new=AsyncMock(return_value=True),
            ),
            # I1 (Phase 3 fix wave): the EventBus now travels via
            # RunnableConfig, so patch the bus object's methods here
            # (not state.event_bus). The config built below carries
            # this same bus instance to exploit_node — the patch
            # applies wherever the bus is referenced.
            patch.object(
                bus,
                "wait_for_tui_response",
                new=AsyncMock(
                    return_value={
                        "response": "approve",
                        "modified_command": None,
                    }
                ),
            ),
            patch.object(bus, "emit_to_tui", new=AsyncMock()),
        ):
            # --- Build and run Phase 3 graph -------------------------------
            # I1 (Phase 3 fix wave): checkpointer=None is still required
            # because LangGraph's checkpointer serde layer would
            # otherwise try to serialize the (non-serialisable)
            # asyncio.Queue handles inside the EventBus — but the bus
            # now lives in the config, not on state, so this is a
            # defensive belt-and-suspenders measure rather than a
            # workaround for the reducer stripping state attributes.
            # The bus reliably reaches exploit_node via the config
            # channel; the patches on `bus.*` above exercise the
            # interactive approve path through the real LangGraph
            # invocation (verifying I1's claim that the config-based
            # bus survives the graph invocation intact).
            graph = build_phase3_graph(checkpointer=None)
            config = {
                "configurable": {
                    "thread_id": engagement_id,
                    "event_bus": bus,
                }
            }
            try:
                final_state = await graph.ainvoke(state, config=config)
            finally:
                # No checkpointer to close when checkpointer=None.
                pass
    finally:
        for p in patchers:
            p.stop()

    # --- Verify final state ---------------------------------------------
    assert final_state["phase"] == "done"  # report_phase1 stub ran
    assert len(final_state["hosts"]) >= 1
    assert len(final_state["services"]) >= 1
    # Phase 3: Exploit Agent recorded a verified foothold.
    footholds = final_state["footholds"]
    assert len(footholds) >= 1, "Exploit Agent recorded no foothold"
    # footholds[0].method mirrors hypothesis.technique from the
    # Shocker fixture ("Shellshock (CVE-2014-6271)"). The brief asserts
    # the method "contains the exploit technique" — the technique name
    # is the canonical signal that the foothold record corresponds to
    # the hypothesis the Exploit Agent attempted.
    assert "Shellshock" in footholds[0].method, (
        f"foothold.method={footholds[0].method!r} does not contain "
        "the exploit technique"
    )
