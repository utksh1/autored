"""End-to-end integration test for the full Phase 4 pipeline (mocked).

Extends the Phase 3 integration test pattern with Post-Ex Agent mocking.
Mocks:

  * LLM (returns ``recon_plan_lame.json`` for the Recon Agent's planning
    call, ``vuln_hypotheses_shocker.json`` for the Vuln Agent's synthesis
    call, an empty ``{"critique": []}`` for the DeepSeek self-critique
    step so the loop converges in one iteration, and
    ``exploit_plan_blue.json`` for the Exploit Agent's planning call).
    The Post-Ex Agent has no LLM dependency in Phase 4 (the
    ``postex_plan_goad.json`` fixture exists for the Phase 5 planner
    that will feed sub-agent args from an LLM), so no Post-Ex LLM mock
    is required here.
  * ``run_subprocess`` for every recon tool module (canned fixture data
    per command name — same as the Phase 1/2/3 integration tests).
  * NVD ``httpx.AsyncClient`` (returns an empty ``{"vulnerabilities":
    []}`` payload so CVEMatcher yields no CVE matches).
  * cross-engagement ``ChromaStore`` (returns no similar findings).
  * all 4 exploit sub-agent tool wrappers (only ``msfagent`` is
    exercised by the Blue plan; the other 3 are patched defensively).
  * ``_verify_foothold`` (returns True so the Exploit Agent records a
    foothold for the Post-Ex Agent to iterate over).
  * all 7 Post-Ex sub-agents (``linuxenum_subagent``,
    ``windowsenum_subagent``, ``privescfinder_subagent``,
    ``credharvester_subagent``, ``persistenceagent_subagent``,
    ``evasionagent_subagent``, ``exfilagent_subagent``) plus the
    ``bloodhound_collect`` tool wrapper. Each returns a typed fixture
    payload so the aggregator fields on ``EngagementState`` end up
    populated with real Pydantic objects the assertions can introspect.

Then runs the full Phase 4 LangGraph end-to-end::

    roe_gate_start -> recon -> vuln -> exploit -> postex -> report_phase1 -> END

Verifies:

  * Final state phase is ``"done"`` (went through ``report_phase1``
    stub after the Post-Ex Agent set ``phase="lateral"``).
  * At least 1 host found, 1 service found, 1 attack hypothesis, 1
    foothold (carried over from Phase 3 expectations).
  * Post-Ex populated state fields (Phase 4 specific):
    - ``local_users`` has at least 1 entry (from windowsenum mock)
    - ``harvested_secrets`` has at least 1 entry (from credharvester mock)
    - ``persistence_artifacts`` has at least 1 entry (from
      persistenceagent mock)
    - ``evasion_actions`` has at least 1 entry (from evasionagent mock)
    - ``exfiltration_proof`` has at least 1 entry (from exfilagent mock)
    - ``bloodhound_collect`` was invoked (windows host + pre-populated
      password secret in ``state.harvested_secrets`` triggers the AD
      collection branch in ``_maybe_run_bloodhound``)
  * Raw tool outputs were saved to ``engagements/<id>/raw/``.

A note on the privesc HitL gate
-------------------------------
The Post-Ex Agent's ``_hitl_privesc_gate`` *always* blocks on
``bus.wait_for_tui_response()`` when the EventBus is present (even in
``auto_approve`` mode — see the helper's docstring). To keep this test
non-blocking we mock ``windowsenum_subagent`` to return an empty
``privesc_candidates`` list — no candidates means no HitL gate fires,
and ``privesc_attempts`` ends up empty. The persistence / evasion /
exfil gates bypass ``wait_for_tui_response`` in ``auto_approve`` mode
and so don't need a pre-fed response either. This is the same
mocking shape used by ``tests/integration/test_postex_agent.py``'s
happy-path test.
"""
import pytest
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from autored.state import EngagementState
from autored.models.roe import RulesOfEngagement
from autored.models.postex import (
    User,
    Secret,
    Trust,
    PersistenceArtifact,
    EvasionAction,
    ExfilEvidence,
)
from autored.persistence.filesystem import init_engagement_folder
from autored.persistence.sqlite_saver import make_checkpointer
from autored.graph import build_phase4_graph
from autored.roe_guard import register_roe
from autored.logging import setup_logging
from autored.tui.event_bus import EventBus
from autored.tools.metasploit import MsfResult


@pytest.mark.asyncio
async def test_phase4_pipeline_mocked(
    tmp_path: Path,
    monkeypatch,
    sandbox_roe_yaml: str,
    fixtures_dir: Path,
):
    """Run the full Phase 4 graph with mocked LLM + subprocesses + EventBus.

    Topology exercised: roe_gate_start → recon → vuln → exploit →
    postex → report_phase1 → END. Every sub-agent (recon tools, exploit
    sub-agents, post-ex sub-agents, BloodHound) is mocked. The Exploit
    Agent's HitL gate auto-approves in sandbox mode (no TUI / no
    operator interaction needed); the Post-Ex Agent's privesc HitL gate
    is bypassed by returning no privesc candidates from the windowsenum
    mock (see module docstring).
    """
    monkeypatch.chdir(tmp_path)
    setup_logging(log_dir=str(tmp_path / "logs"))

    # ------------------------------------------------------------------
    # 1. Register RoE + init engagement folder
    # ------------------------------------------------------------------
    roe = RulesOfEngagement.model_validate_yaml(sandbox_roe_yaml)
    engagement_id = "test-pipeline-004"
    register_roe(engagement_id, roe)
    init_engagement_folder(engagement_id, "10.10.10.40", "test")

    # ------------------------------------------------------------------
    # 2. Mock the LLM responses, dispatched by router task name:
    #    - "plan_recon"         → recon_plan_lame.json (3-step plan)
    #    - "synthesize_findings" → vuln_hypotheses_shocker.json
    #    - "second_opinion"     → empty critique (self-critique converges)
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
    # 3. Mock run_subprocess for every recon tool module
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
    # 4. Mock all 4 exploit sub-agent tool wrappers (Phase 3 pattern)
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
    # 5. Mock all 7 Post-Ex sub-agents + bloodhound_collect.
    #    Each returns a typed Pydantic payload so the aggregator fields
    #    on EngagementState end up populated with real objects the
    #    assertions can introspect. ``privesc_candidates`` is left empty
    #    on the windowsenum mock so the privesc HitL gate never fires
    #    (see module docstring).
    # ------------------------------------------------------------------
    fake_user = User(
        host_ip="10.10.10.40", username="Administrator",
        uid="S-1-5-21-...-500", groups=["Domain Admins"], is_admin=True,
    )
    fake_trust = Trust(
        host_ip="10.10.10.40", trust_type="ad_domain",
        target="lab.local", details={"forest": "lab.local"},
    )
    fake_cred_secret = Secret(
        host_ip="10.10.10.40", secret_type="password",
        secret_value="P@ssw0rd!", source="mimikatz",
    )
    fake_persist_artifact = PersistenceArtifact(
        host_ip="10.10.10.40", method="scheduled_task",
        details={"task_name": "autored_persist"},
        removal_command="schtasks /delete /tn autored_persist /f",
        foothold_id="placeholder",  # exploit_node assigns the real id
    )
    fake_evasion_action = EvasionAction(
        host_ip="10.10.10.40", technique="amsi_bypass",
        target="amsi.dll", success=True,
        command="[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
    )
    fake_exfil_evidence = ExfilEvidence(
        method="https", source_host="10.10.10.40",
        data_size_bytes=2048, catch_server="catch.autored.local",
        catch_server_log_path="/var/log/catch/10.10.10.40_20260921.log",
    )

    mock_windowsenum = MagicMock()
    mock_windowsenum.ainvoke = AsyncMock(return_value=MagicMock(
        users=[fake_user],
        secrets=[],  # secrets come from credharvester
        trusts=[fake_trust],
        privesc_candidates=[],  # empty → no privesc HitL gate fires
    ))
    mock_linuxenum = MagicMock()
    mock_linuxenum.ainvoke = AsyncMock(return_value=MagicMock(
        users=[], secrets=[], trusts=[], privesc_candidates=[],
    ))
    mock_privescfinder = MagicMock()
    mock_privescfinder.ainvoke = AsyncMock(return_value=MagicMock(
        candidates=[], attempts=[],
    ))
    mock_credharvester = MagicMock()
    mock_credharvester.ainvoke = AsyncMock(return_value=MagicMock(
        secrets=[fake_cred_secret],
    ))
    mock_persistenceagent = MagicMock()
    mock_persistenceagent.ainvoke = AsyncMock(return_value=MagicMock(
        artifacts=[fake_persist_artifact],
    ))
    mock_evasionagent = MagicMock()
    mock_evasionagent.ainvoke = AsyncMock(return_value=MagicMock(
        actions=[fake_evasion_action],
    ))
    mock_exfilagent = MagicMock()
    mock_exfilagent.ainvoke = AsyncMock(return_value=MagicMock(
        evidence=fake_exfil_evidence,
    ))
    mock_bloodhound = MagicMock()
    mock_bloodhound.ainvoke = AsyncMock(return_value=MagicMock(
        success=True, zip_path="/tmp/bloodhound_lab.zip",
    ))

    # ------------------------------------------------------------------
    # 6. Build initial state. Inject an EventBus so every HitL gate in
    #    the Exploit + Post-Ex Agents has somewhere to emit events
    #    (sandbox auto_approve means persistence / evasion / exfil gates
    #    return without blocking; the privesc gate is bypassed because
    #    we returned no candidates — see module docstring). Pre-populate
    #    ``harvested_secrets`` with one password Secret so the
    #    ``_maybe_run_bloodhound`` AD-creds check passes and the mock
    #    bloodhound_collect gets exercised.
    # ------------------------------------------------------------------
    state = EngagementState(
        engagement_id=engagement_id,
        target_scope=["10.10.10.40"],
        operator="test",
        rules_of_engagement=roe,
    )
    state.event_bus = EventBus()
    # Pre-populate so _maybe_run_bloodhound's AD-creds check passes.
    # postex_node returns ``state.harvested_secrets + all_secrets`` so
    # this pre-existing entry persists through to the final state.
    state.harvested_secrets = [
        Secret(
            host_ip="10.10.10.40", secret_type="password",
            secret_value="pre-populated", source="setup",
        )
    ]

    # ------------------------------------------------------------------
    # 7. Build graph + run with all mocks in place
    # ------------------------------------------------------------------
    from contextlib import ExitStack

    checkpointer = await make_checkpointer(engagement_id)
    try:
        graph = build_phase4_graph(checkpointer)
        config = {"configurable": {"thread_id": engagement_id}}

        # We have ~20 patches to apply simultaneously — Python's static
        # nesting limit caps plain ``with`` chains at ~20 levels. Use an
        # ``ExitStack`` so we can enter every patcher in a single
        # ``with`` block (the limit is on nesting depth, not on the
        # number of contexts entered via ``ExitStack.enter_context``).
        with ExitStack() as stack:
            stack.enter_context(patch("autored.agents.recon.get_model", side_effect=mock_get_model))
            stack.enter_context(patch("autored.agents.vuln.get_model", side_effect=mock_get_model))
            stack.enter_context(patch(
                "autored.subagents.hypothesiscritic.get_model",
                side_effect=mock_get_model,
            ))
            stack.enter_context(patch("autored.agents.exploit.get_model", side_effect=mock_get_model))
            mock_httpx_cls = stack.enter_context(patch("autored.tools.nvd.httpx.AsyncClient"))
            mock_chroma_cls = stack.enter_context(patch("autored.agents.vuln.ChromaStore"))
            stack.enter_context(patch("autored.subagents.msfagent.metasploit_rpc", new=mock_msf_tool))
            stack.enter_context(patch("autored.subagents.sqliagent.sqlmap_run", new=mock_sqli_tool))
            stack.enter_context(patch("autored.subagents.bruteagent.hydra_brute", new=mock_brute_tool))
            stack.enter_context(patch("autored.subagents.customagent.custom_command", new=mock_custom_tool))
            stack.enter_context(patch("autored.agents.exploit._verify_foothold", return_value=True))
            stack.enter_context(patch("autored.agents.postex.windowsenum_subagent", new=mock_windowsenum))
            stack.enter_context(patch("autored.agents.postex.linuxenum_subagent", new=mock_linuxenum))
            stack.enter_context(patch("autored.agents.postex.privescfinder_subagent", new=mock_privescfinder))
            stack.enter_context(patch("autored.agents.postex.credharvester_subagent", new=mock_credharvester))
            stack.enter_context(patch("autored.agents.postex.persistenceagent_subagent", new=mock_persistenceagent))
            stack.enter_context(patch("autored.agents.postex.evasionagent_subagent", new=mock_evasionagent))
            stack.enter_context(patch("autored.agents.postex.exfilagent_subagent", new=mock_exfilagent))
            stack.enter_context(patch("autored.agents.postex.bloodhound_collect", new=mock_bloodhound))

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

            for mod in tool_modules:
                stack.enter_context(patch(f"{mod}.run_subprocess", new=mock_run_subprocess))

            final_state = await graph.ainvoke(state, config=config)
    finally:
        # AsyncSqliteSaver holds an open aiosqlite connection — close it
        # so pytest-asyncio's event loop tears down cleanly.
        conn = getattr(checkpointer, "conn", None)
        if conn is not None:
            await conn.close()

    # ------------------------------------------------------------------
    # 8. Verify final state — Phase 3 carried-over expectations
    # ------------------------------------------------------------------
    assert isinstance(final_state, dict)
    # postex_node sets phase="lateral", then report_phase1 stub
    # overwrites phase="done". Either is acceptable for forward-compat
    # with Phase 5 (which will preserve "lateral" past the postex node).
    assert final_state["phase"] in ("done", "lateral"), (
        f"Expected phase 'done' or 'lateral', got {final_state['phase']!r}"
    )

    hosts = final_state["hosts"]
    assert len(hosts) >= 1, f"expected at least 1 host, got {len(hosts)}"

    services = final_state["services"]
    assert len(services) >= 1, f"expected at least 1 service, got {len(services)}"

    hypotheses = final_state["attack_hypotheses"]
    assert isinstance(hypotheses, list)
    assert len(hypotheses) >= 1, (
        f"expected at least 1 attack hypothesis, got {len(hypotheses)}"
    )

    # Exploit Agent should have recorded a foothold — this is what the
    # Post-Ex Agent iterates over.
    footholds = final_state["footholds"]
    assert len(footholds) >= 1, (
        f"expected at least 1 foothold after exploit, got {len(footholds)}"
    )

    # ------------------------------------------------------------------
    # 9. Verify final state — Phase 4 Post-Ex populated fields
    # ------------------------------------------------------------------
    local_users = final_state["local_users"]
    assert len(local_users) >= 1, (
        f"expected at least 1 local user from post-ex, got {len(local_users)}"
    )

    harvested_secrets = final_state["harvested_secrets"]
    # 1 pre-populated + 1 from credharvester mock = 2 minimum
    assert len(harvested_secrets) >= 2, (
        f"expected at least 2 harvested secrets (1 pre-pop + 1 from "
        f"credharvester), got {len(harvested_secrets)}"
    )

    trust_relationships = final_state["trust_relationships"]
    assert len(trust_relationships) >= 1, (
        f"expected at least 1 trust relationship, got {len(trust_relationships)}"
    )

    persistence_artifacts = final_state["persistence_artifacts"]
    assert len(persistence_artifacts) >= 1, (
        f"expected at least 1 persistence artifact, got {len(persistence_artifacts)}"
    )

    evasion_actions = final_state["evasion_actions"]
    assert len(evasion_actions) >= 1, (
        f"expected at least 1 evasion action, got {len(evasion_actions)}"
    )

    exfiltration_proof = final_state["exfiltration_proof"]
    assert len(exfiltration_proof) >= 1, (
        f"expected at least 1 exfil proof, got {len(exfiltration_proof)}"
    )

    # BloodHound should have been called (Windows foothold + pre-populated
    # password secret in state.harvested_secrets satisfies the AD-creds
    # check in _maybe_run_bloodhound).
    mock_bloodhound.ainvoke.assert_awaited()
    # WindowsEnum should have been called (the ms17_010 foothold's
    # access_type defaults to "shell", which _determine_os_type maps to
    # "windows"). LinuxEnum should NOT have been called.
    mock_windowsenum.ainvoke.assert_awaited()
    mock_linuxenum.ainvoke.assert_not_called()
    # CredHarvester, Persistence, Evasion, Exfil all ran (sandbox RoE
    # allows every sub-activity).
    mock_credharvester.ainvoke.assert_awaited()
    mock_persistenceagent.ainvoke.assert_awaited()
    mock_evasionagent.ainvoke.assert_awaited()
    mock_exfilagent.ainvoke.assert_awaited()

    # ------------------------------------------------------------------
    # 10. Verify raw outputs were saved to engagements/<id>/raw/
    # ------------------------------------------------------------------
    raw_dir = tmp_path / "engagements" / engagement_id / "raw"
    assert raw_dir.exists(), f"raw dir not found at {raw_dir}"
    out_files = list(raw_dir.glob("*.out"))
    assert len(out_files) >= 1, f"no .out files in {raw_dir}"
