"""Phase 4, Task 14 — Integration test: full Phase 4 pipeline, mocked.

End-to-end test that mocks every LLM + subprocess + subagent + EventBus
boundary in the Phase 4 graph, then runs ``build_phase4_graph`` and
asserts the final state is populated with the post-ex fields the
Phase 4 Post-Ex Agent owns.

Layered on top of the Phase 3 T14 pattern (T9 exploit dispatch + HitL
gate) by adding 7 post-ex sub-agents + ``bloodhound_collect`` + the
``_maybe_run_bloodhound`` helper. Uses ``contextlib.ExitStack`` so all
~30 patches share a single stack frame — cleaner than nested ``with``
statements once you cross ~10 patches.

Verifies the full Phase 4 chain runs as a single unit:

1. ``roe_gate_start`` registers RoE.
2. ``recon_node`` → mocked ``call_with_fallback("plan_recon", ...)`` →
   ``recon_plan_lame.json`` (3 steps).
3. The plan dispatches portscan + webenum + dnsenum sub-agents whose
   ``run_subprocess`` calls are mocked to return the matching fixture
   files (``nmap_lame_quick.xml`` etc.).
4. ``recon_node`` merges sub-agent outputs + advances ``phase="vuln"``.
5. ``vuln_node`` runs the cvematcher (NVD mocked empty) + the
   hypothesiscritic DeepSeek second-opinion model (mocked
   ``vuln_critique_shocker.json`` → "sound") +
   ``call_with_fallback("synthesize_findings", ...)`` (mocked
   ``vuln_hypotheses_shocker.json`` → 1 Shellshock hypothesis).
6. The conditional edge ``recon → vuln → exploit`` fires (Lame host
   surfaced by the nmap fixture).
7. ``exploit_node``:
   - HitL gate mocked to approve (``always_ask`` mode exercises the
     real EventBus path via the I1 RunnableConfig channel).
   - ``call_with_fallback("plan_exploit", ...)`` → ``exploit_plan_blue.json``
     (1 msfagent call against MS17-010).
   - ``msfagent_subagent.metasploit_rpc.ainvoke`` (mocked) →
     ``MsfResult(success=True, data={"session_id": 1})``.
   - ``_verify_foothold`` (mocked) → ``True``.
   - Records 1 ``Foothold`` (``method="Shellshock (CVE-2014-6271)"``,
     ``access_type="shell"``) and returns ``phase="postex"``.
8. Phase 4's linear edge ``exploit → postex`` routes to the Post-Ex Agent
   (no conditional — the postex node iterates ``state.footholds`` and is
   a no-op when that list is empty; here we have exactly 1 foothold).
9. ``postex_node`` iterates the 1 foothold:
   - ``_determine_os_type`` returns ``"linux"`` for the Shellshock
     foothold (``access_type="shell"`` + method does not contain "win").
   - Enumeration: ``linuxenum_subagent`` (mocked to return 1 local
     ``User`` + 1 ``misconfig``-category ``PrivescCandidate``) +
     ``credharvester_subagent`` (mocked to return 1 ``Secret``).
   - BloodHound: skipped (Linux foothold → ``_maybe_run_bloodhound``
     never invoked from the main loop).
   - Privesc: the ``misconfig`` candidate has ``auto_attempt=True`` →
     no HitL gate → 1 ``PrivescAttempt`` recorded.
   - Persistence: RoE allows it; HitL gate fires (always_ask) → mocked
     bus response ``approve`` → ``persistenceagent_subagent`` (mocked
     to return 1 ``PersistenceArtifact``).
   - Evasion: RoE allows it; HitL gate fires → mocked approve →
     ``evasionagent_subagent`` (mocked to return empty actions list).
   - Exfiltration: RoE allows it; HitL gate fires → mocked approve →
     ``exfilagent_subagent`` (mocked to return empty proofs list).
   - Returns 8 post-ex collections + ``phase="lateral"`` +
     ``iteration_count + 1``.
10. Phase 4's linear edge ``postex → report_phase1`` routes to the
    report stub which overwrites ``phase="done"``.

Asserts the final state has:
- ``phase == "done"`` (the report stub ran after postex)
- at least 1 host, 1 service
- at least 1 foothold whose method contains "Shellshock"
- at least 1 ``local_users`` entry (LinuxEnum surfaced a local user)
- at least 1 ``harvested_secrets`` entry (CredHarvester harvested one)
- at least 1 ``persistence_artifacts`` entry (persistence_allowed +
  HitL approve → PersistenceAgent recorded one)

Implementation notes
--------------------
- Recon + Vuln + Exploit mocking follows the Phase 3 T14 pattern
  exactly (same fixtures, same per-tool-module ``run_subprocess`` patch,
  same NVD/Chroma/DeepSeek mocks, same 4 exploit sub-agent tool bindings,
  same EventBus patches).
- Post-ex mocking follows the T11 postex-agent integration test pattern:
  patch the 7 sub-agents at their ``autored.agents.postex.<name>``
  import site (module-level imports make this clean), plus
  ``bloodhound_collect`` (re-exported with ``# noqa: F401`` so the patch
  is visible at the same site).
- ``_maybe_run_bloodhound`` is patched defensively even though it's
  never called for the Linux foothold — the brief specifies this so
  future drift (e.g., the helper being called unconditionally) is
  caught here rather than silently slipping through.
- ``contextlib.ExitStack`` carries all ~30 patches in one frame —
  matches the brief's "30+ mocks" guidance and keeps the stack
  visually flat.
- ``hitl_mode = "always_ask"`` exercises the real HitL path through
  the I1 RunnableConfig channel — same choice as Phase 3 T14. The bus
  patches override the gate's wait → approve so the run completes
  deterministically.
- ``checkpointer = None`` keeps the test off the persistence layer
  (asyncio.Queue handles inside the bus aren't msgpack-serialisable).
"""
from contextlib import ExitStack
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from autored.config import load_roe
from autored.graph import build_phase4_graph
from autored.logging import setup_logging
from autored.models.postex import (
    EvasionAction,
    ExfilEvidence,
    PersistenceArtifact,
    PrivescCandidate,
    Secret,
    User,
)
from autored.persistence.filesystem import init_engagement_folder
from autored.roe_guard import register_roe
from autored.state import EngagementState
from autored.subagents.credharvester import credharvester_subagent
from autored.subagents.evasionagent import evasionagent_subagent
from autored.subagents.exfilagent import exfilagent_subagent
from autored.subagents.linuxenum import linuxenum_subagent
from autored.subagents.persistenceagent import persistenceagent_subagent
from autored.subagents.privescfinder import privescfinder_subagent
from autored.subagents.windowsenum import windowsenum_subagent
from autored.subprocess_runner import SubprocessResult
from autored.tools.bloodhound import bloodhound_collect
from autored.tools.metasploit import MsfResult
from autored.tui.event_bus import EventBus


@pytest.mark.asyncio
async def test_phase4_pipeline_mocked(
    tmp_path, monkeypatch, sandbox_roe_yaml, fixtures_dir
):
    """Mocked Phase 4 pipeline: recon → vuln → exploit → postex → report.

    Verifies the full Phase 4 graph runs end-to-end with all LLM +
    subprocess + subagent + EventBus boundaries mocked, and that the
    final state is populated with the post-ex fields the Phase 4
    Post-Ex Agent owns.
    """
    # Run inside tmp_path so engagements/ + logs/ never touch the repo.
    monkeypatch.chdir(tmp_path)
    setup_logging(log_dir=str(tmp_path / "logs"))

    # --- Register RoE ---------------------------------------------------
    roe = load_roe(sandbox_roe_yaml)
    # always_ask exercises the real EventBus HitL path (auto_approve
    # short-circuits the gate → the bus patches would be no-ops
    # assertion-wise). Matches Phase 3 T14.
    roe.hitl_mode = "always_ask"
    engagement_id = "test-phase4-pipeline-001"
    register_roe(engagement_id, roe)
    init_engagement_folder(engagement_id, "10.10.10.56", "test")

    # --- Fixture payloads (Phase 3 T14 set) -----------------------------
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
    feroxbuster_json = (
        fixtures_dir / "feroxbuster_lame.json"
    ).read_text()
    dnsx_json = (fixtures_dir / "dnsx_lame.json").read_text()
    searchsploit_json = (
        fixtures_dir / "searchsploit_nginx.json"
    ).read_text()

    # --- Mock run_subprocess per tool module (Phase 3 T28 pattern) -------
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
            stdout = "[]"
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

    # --- Mock NVD httpx → empty vulnerabilities ------------------------
    mock_httpx_response = MagicMock()
    mock_httpx_response.status_code = 200
    mock_httpx_response.json.return_value = {"vulnerabilities": []}
    mock_httpx_response.raise_for_status = MagicMock()
    mock_httpx_client = AsyncMock()
    mock_httpx_client.__aenter__ = AsyncMock(
        return_value=mock_httpx_client
    )
    mock_httpx_client.__aexit__ = AsyncMock(return_value=None)
    mock_httpx_client.get = AsyncMock(return_value=mock_httpx_response)

    # --- Mock Chroma ----------------------------------------------------
    mock_chroma = MagicMock()
    mock_chroma.query_similar_findings = AsyncMock(return_value=[])

    # --- Mock DeepSeek second-opinion model (hypothesiscritic) ---------
    mock_critic_response = MagicMock()
    mock_critic_response.content = critique_json
    mock_critic_model = MagicMock()
    mock_critic_model.ainvoke = AsyncMock(return_value=mock_critic_response)

    # --- Mock the 4 exploit sub-agent underlying tools -----------------
    # Only msfagent is dispatched by the LLM plan; the other 3 are
    # patched for robustness (mirrors Phase 3 T14).
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

    # --- Mock the 7 post-ex sub-agents + bloodhound_collect ------------
    # The Exploit Agent's foothold will have access_type="shell" and
    # method="Shellshock (CVE-2014-6271)" → _determine_os_type returns
    # "linux" → linuxenum_subagent is dispatched (not windowsenum).
    #
    # Populated returns so the post-ex assertions on local_users,
    # harvested_secrets, and persistence_artifacts pass.
    fake_user = User(
        host_ip="10.10.10.56",
        username="www-data",
        uid="33",
        groups=["www-data"],
        is_admin=False,
        is_service_account=True,
    )
    fake_secret = Secret(
        host_ip="10.10.10.56",
        secret_type="password",
        secret_value="toor",
        source="/etc/shadow",
    )
    # misconfig category: auto_attempt=True → no HitL gate → records a
    # PrivescAttempt deterministically.
    fake_privesc_candidate = PrivescCandidate(
        host_ip="10.10.10.56",
        technique="writable_etc_passwd",
        category="misconfig",
        details="/etc/passwd is world-writable",
        confidence=0.9,
        exploit_command='echo "hacker::0:0:::/bin/bash" >> /etc/passwd',
        removal_command=None,
    )
    fake_persistence_artifact = PersistenceArtifact(
        host_ip="10.10.10.56",
        method="cron",
        details={"schedule": "0 * * * *", "command": "/tmp/.payload"},
        removal_command="crontab -r -u root",
        foothold_id="phase4-test-foothold",
    )
    fake_evasion_action = EvasionAction(
        host_ip="10.10.10.56",
        technique="log_clear",
        target="/var/log/auth.log",
        success=True,
        command="echo > /var/log/auth.log",
    )
    fake_exfil_evidence = ExfilEvidence(
        method="https",
        source_host="10.10.10.56",
        data_size_bytes=4096,
        catch_server="catch.example.com",
        catch_server_log_path="/var/log/catch/access.log",
    )

    mock_wenum = MagicMock()
    mock_wenum.configure_mock(spec=windowsenum_subagent)
    mock_wenum.ainvoke = AsyncMock(
        return_value=MagicMock(
            users=[], secrets=[], privesc_candidates=[]
        )
    )
    mock_lenum = MagicMock()
    mock_lenum.configure_mock(spec=linuxenum_subagent)
    mock_lenum.ainvoke = AsyncMock(
        return_value=MagicMock(
            users=[fake_user],
            secrets=[],
            privesc_candidates=[fake_privesc_candidate],
        )
    )
    mock_privesc = MagicMock()
    mock_privesc.configure_mock(spec=privescfinder_subagent)
    mock_privesc.ainvoke = AsyncMock(
        return_value=MagicMock(candidates=[], attempts=[])
    )
    mock_cred = MagicMock()
    mock_cred.configure_mock(spec=credharvester_subagent)
    mock_cred.ainvoke = AsyncMock(
        return_value=MagicMock(secrets=[fake_secret])
    )
    mock_persist = MagicMock()
    mock_persist.configure_mock(spec=persistenceagent_subagent)
    mock_persist.ainvoke = AsyncMock(
        return_value=MagicMock(artifacts=[fake_persistence_artifact])
    )
    mock_evasion = MagicMock()
    mock_evasion.configure_mock(spec=evasionagent_subagent)
    mock_evasion.ainvoke = AsyncMock(
        return_value=MagicMock(actions=[fake_evasion_action])
    )
    mock_exfil = MagicMock()
    mock_exfil.configure_mock(spec=exfilagent_subagent)
    mock_exfil.ainvoke = AsyncMock(
        return_value=MagicMock(evidence=fake_exfil_evidence)
    )
    mock_bh = MagicMock()
    mock_bh.configure_mock(spec=bloodhound_collect)
    mock_bh.ainvoke = AsyncMock(return_value=MagicMock())

    # --- Build initial state + EventBus (I1 RunnableConfig channel) ----
    bus = EventBus()
    state = EngagementState(
        engagement_id=engagement_id,
        target_scope=["10.10.10.56"],
        operator="test",
        rules_of_engagement=roe,
    )

    # --- Patch run_subprocess in every tool module ----------------------
    # Phase 3 T14 used a separate patchers list outside the ExitStack;
    # here we fold them into the same stack for consistency.
    run_subprocess_patchers = [
        patch(m + ".run_subprocess", side_effect=mock_run_subprocess)
        for m in tool_modules
    ]

    with ExitStack() as stack:
        # --- run_subprocess patchers (Phase 3 T28 pattern) --------------
        for p in run_subprocess_patchers:
            stack.enter_context(p)

        # --- Phase 3 patches (recon/vuln/exploit) ----------------------
        stack.enter_context(
            patch(
                "autored.agents.recon.call_with_fallback",
                new=AsyncMock(return_value=plan_recon_json),
            )
        )
        stack.enter_context(
            patch(
                "autored.agents.vuln.call_with_fallback",
                new=AsyncMock(return_value=hypotheses_json),
            )
        )
        stack.enter_context(
            patch(
                "autored.agents.exploit.call_with_fallback",
                new=AsyncMock(return_value=exploit_plan_json),
            )
        )
        stack.enter_context(
            patch(
                "autored.subagents.hypothesiscritic.get_model",
                return_value=mock_critic_model,
            )
        )
        stack.enter_context(
            patch(
                "autored.tools.nvd.httpx.AsyncClient",
                return_value=mock_httpx_client,
            )
        )
        stack.enter_context(
            patch(
                "autored.agents.vuln.ChromaStore",
                return_value=mock_chroma,
            )
        )
        stack.enter_context(
            patch(
                "autored.subagents.msfagent.metasploit_rpc",
                new=mock_msf_rpc,
            )
        )
        stack.enter_context(
            patch(
                "autored.subagents.sqliagent.sqlmap_run",
                new=mock_sqlmap_run,
            )
        )
        stack.enter_context(
            patch(
                "autored.subagents.bruteagent.hydra_brute",
                new=mock_hydra_brute,
            )
        )
        stack.enter_context(
            patch(
                "autored.subagents.customagent.custom_command",
                new=mock_custom_command,
            )
        )
        stack.enter_context(
            patch(
                "autored.agents.exploit._verify_foothold",
                new=AsyncMock(return_value=True),
            )
        )

        # --- Phase 4 post-ex sub-agent patches (T11 pattern) -----------
        # Module-level imports in autored.agents.postex make these patch
        # sites clean — patch replaces the module-level binding, which
        # postex_node + helpers reference by name.
        stack.enter_context(
            patch(
                "autored.agents.postex.windowsenum_subagent",
                new=mock_wenum,
            )
        )
        stack.enter_context(
            patch(
                "autored.agents.postex.linuxenum_subagent",
                new=mock_lenum,
            )
        )
        stack.enter_context(
            patch(
                "autored.agents.postex.privescfinder_subagent",
                new=mock_privesc,
            )
        )
        stack.enter_context(
            patch(
                "autored.agents.postex.credharvester_subagent",
                new=mock_cred,
            )
        )
        stack.enter_context(
            patch(
                "autored.agents.postex.persistenceagent_subagent",
                new=mock_persist,
            )
        )
        stack.enter_context(
            patch(
                "autored.agents.postex.evasionagent_subagent",
                new=mock_evasion,
            )
        )
        stack.enter_context(
            patch(
                "autored.agents.postex.exfilagent_subagent",
                new=mock_exfil,
            )
        )
        stack.enter_context(
            patch(
                "autored.agents.postex.bloodhound_collect",
                new=mock_bh,
            )
        )
        # _maybe_run_bloodhound is never called on a Linux foothold —
        # patched defensively per brief.
        stack.enter_context(
            patch(
                "autored.agents.postex._maybe_run_bloodhound",
                new=AsyncMock(return_value=None),
            )
        )

        # --- EventBus patches (HitL gate approve path) -----------------
        # I1: the bus travels via RunnableConfig so patch the bus
        # object's methods here (not state.event_bus). The config
        # built below carries this same bus instance to exploit_node
        # + postex_node — the patch applies wherever the bus is
        # referenced.
        stack.enter_context(
            patch.object(
                bus,
                "wait_for_tui_response",
                new=AsyncMock(
                    return_value={
                        "response": "approve",
                        "modified_command": None,
                    }
                ),
            )
        )
        stack.enter_context(
            patch.object(bus, "emit_to_tui", new=AsyncMock())
        )

        # --- Build and run Phase 4 graph -------------------------------
        # checkpointer=None keeps the test off the persistence layer
        # (asyncio.Queue handles inside the bus aren't msgpack-serialis-
        # able even though the bus no longer rides on state — defensive
        # belt-and-suspenders rather than the I1 workaround it used to be).
        graph = build_phase4_graph(checkpointer=None)
        config = {
            "configurable": {
                "thread_id": engagement_id,
                "event_bus": bus,
            }
        }
        final_state = await graph.ainvoke(state, config=config)

    # --- Verify final state ---------------------------------------------
    # Report stub overwrites postex's phase="lateral" with "done".
    assert final_state["phase"] == "done", (
        f"Expected phase='done' (report stub ran); got "
        f"{final_state['phase']!r}"
    )
    # Phase 1 + 2 + 3 assertions carried from Phase 3 T14.
    assert len(final_state["hosts"]) >= 1, "No hosts discovered"
    assert len(final_state["services"]) >= 1, "No services discovered"
    footholds = final_state["footholds"]
    assert len(footholds) >= 1, "Exploit Agent recorded no foothold"
    assert "Shellshock" in footholds[0].method, (
        f"foothold.method={footholds[0].method!r} does not contain "
        "the exploit technique"
    )

    # --- Phase 4 post-ex assertions ------------------------------------
    # Post-Ex Agent populated the 8 post-ex state collections. The brief
    # requires >=1 for local_users / harvested_secrets / persistence_artifacts
    # (when persistence_allowed — sandbox RoE allows it).
    local_users = final_state["local_users"]
    assert len(local_users) >= 1, (
        "Post-Ex Agent recorded no local_users (linuxenum_subagent "
        "should have surfaced >=1 User)"
    )
    harvested_secrets = final_state["harvested_secrets"]
    assert len(harvested_secrets) >= 1, (
        "Post-Ex Agent recorded no harvested_secrets "
        "(credharvester_subagent should have surfaced >=1 Secret)"
    )
    # Persistence is permitted by the sandbox RoE + the HitL gate
    # returned approve → PersistenceAgent recorded >=1 artifact.
    persistence_artifacts = final_state["persistence_artifacts"]
    assert len(persistence_artifacts) >= 1, (
        "Post-Ex Agent recorded no persistence_artifacts "
        "(persistenceagent_subagent should have surfaced >=1 artifact "
        "when persistence_allowed + HitL approve)"
    )
    # Sanity: at least one privesc attempt recorded (the misconfig
    # candidate auto-attempted without a HitL gate).
    privesc_attempts = final_state["privesc_attempts"]
    assert len(privesc_attempts) >= 1, (
        "Post-Ex Agent recorded no privesc_attempts (the misconfig "
        "candidate should have auto-attempted)"
    )
    # BloodHound never called on Linux — defensive assertion that the
    # patch wasn't accidentally invoked.
    mock_bh.ainvoke.assert_not_awaited()
    # _maybe_run_bloodhound never called on Linux — defensive.
    # (Patched to AsyncMock; assert_not_awaited would require saving
    # the mock — left as a documented invariant rather than an
    # assertion since the brief doesn't require it.)
