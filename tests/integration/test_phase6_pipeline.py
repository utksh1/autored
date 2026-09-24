"""Phase 6, Task 10 — Integration test: full Phase 6 pipeline, mocked.

End-to-end test that mocks every LLM + subprocess + subagent + EventBus
boundary in the Phase 6 graph, then runs ``build_phase6_graph`` and
asserts the final state is populated with the Phase 6 deliverables
the Report Agent owns.

Layered on top of the Phase 5 T14 mock lattice by adding the report
sub-agent + render_pdf + persist_engagement_memory layer:

* ``mitremapper_subagent`` — returns a one-row MITRE mapping
  (``T1210`` / "Exploitation of Remote Services" / ``lateral-movement``,
  sourced from the pre-seeded foothold).
* ``execsummarywriter_subagent`` — returns the LLM-shaped exec
  summary markdown (no fallback).
* ``techreportwriter_subagent`` — returns the LLM-shaped technical
  report markdown (no fallback).
* ``lessonextractor_subagent`` — returns one typed ``Lesson`` row
  (``technique_worked`` category, MITRE-linked).
* ``render_pdf`` — returns ``None`` (WeasyPrint unavailable path —
  exercises the graceful-degradation branch in the Report Agent).
* ``persist_engagement_memory`` — returns a successful
  ``MemoryWriteResult`` (no DB error, no Chroma error). The cross-
  engagement SQLite writes are also tested in isolation by
  ``tests/unit/reporting/test_memory_writer.py`` — the pipeline test
  only needs the call to be made without raising.

The Phase 1-3 LLM / recon-tool / NVD / Chroma / DeepSeek / exploit
sub-agent / ``_verify_foothold`` mock lattice is copied verbatim from
``tests/integration/test_phase5_pipeline.py`` — the Phase 4 post-ex
sub-agent layer (windowsenum / linuxenum / privescfinder /
credharvester / persistenceagent / evasionagent / exfilagent +
bloodhound_collect + ``_maybe_run_bloodhound``) is also copied
verbatim, as is the Phase 5 lateral / cleanup sub-agent layer. The
Phase 6 report layer is appended on top inside the same
``contextlib.ExitStack`` (~36+ patches — well past Python's static
``with`` nesting limit, but ExitStack handles it).

Verifies the full Phase 6 chain runs as a single unit::

    roe_gate_start → recon → vuln → exploit → postex → lateral →
    cleanup → report → END

Asserts the final state carries:

* Phase 1-5 carry-overs: phase == "done", ≥1 host / service / foothold,
  ≥1 local_users / harvested_secrets / persistence_artifacts, ≥1 pivot,
  ≥1 sub_engagement, ≥2 verified cleanup_results.
* Phase 6 specific: ``report_paths`` is populated with a markdown
  path + lessons path that exist on disk and are non-empty; ≥1 lesson;
  ≥1 MITRE mapping; truthy one-line summary (the engagement outcome).
"""
import shutil
from contextlib import ExitStack
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from autored.config import load_roe
from autored.graph import build_phase6_graph
from autored.logging import setup_logging
from autored.models.host import Host
from autored.models.foothold import Foothold
from autored.models.lateral import (
    MovementPath,
    PivotCandidate,
    PivotRecord,
    SubEngagementRef,
)
from autored.models.cleanup import CleanupResult
from autored.models.postex import (
    EvasionAction,
    ExfilEvidence,
    PersistenceArtifact,
    PrivescCandidate,
    Secret,
    User,
)
from autored.models.report import Lesson, MitreMapping
from autored.persistence.filesystem import init_engagement_folder
from autored.roe_guard import register_roe
from autored.state import EngagementState
from autored.subagents.artifactremover import (
    ArtifactRemoverOutput,
    artifactremover_subagent,
)
from autored.subagents.credharvester import credharvester_subagent
from autored.subagents.evasionagent import evasionagent_subagent
from autored.subagents.exfilagent import exfilagent_subagent
from autored.subagents.linuxenum import linuxenum_subagent
from autored.subagents.persistenceagent import persistenceagent_subagent
from autored.subagents.pivotexecutor import PivotExecutorOutput
from autored.subagents.privescfinder import privescfinder_subagent
from autored.subagents.verificationscanner import (
    VerificationScannerOutput,
    verificationscanner_subagent,
)
from autored.subagents.windowsenum import windowsenum_subagent
from autored.subprocess_runner import SubprocessResult
from autored.subagents.pivotexecutor import pivotexecutor_subagent
from autored.subagents.tunnelsetup import tunnelsetup_subagent
from autored.tools.bloodhound import bloodhound_collect
from autored.tools.metasploit import MsfResult
from autored.tui.event_bus import EventBus


def _mitre_mock() -> MagicMock:
    """Return a mocked MITREMapper sub-agent with one T1210 mapping."""
    mock = MagicMock()
    mock.ainvoke = AsyncMock(return_value=MagicMock(mappings=[MitreMapping(
        technique_id="T1210", technique_name="Exploitation of Remote Services",
        tactic="lateral-movement", source="foothold", detail="ms17_010",
    )]))
    return mock


def _exec_mock() -> MagicMock:
    """Return a mocked ExecSummaryWriter sub-agent (LLM path, no fallback)."""
    mock = MagicMock()
    mock.ainvoke = AsyncMock(return_value=MagicMock(
        summary_markdown="## Executive Summary\n\nFull chain achieved.",
        used_fallback=False))
    return mock


def _tech_mock() -> MagicMock:
    """Return a mocked TechReportWriter sub-agent (LLM path, no fallback)."""
    mock = MagicMock()
    mock.ainvoke = AsyncMock(return_value=MagicMock(
        report_markdown="## Attack Narrative\n\nStory.\n\n## Scope\n\n- t",
        used_fallback=False))
    return mock


def _lesson_mock() -> MagicMock:
    """Return a mocked LessonExtractor sub-agent with one typed Lesson."""
    mock = MagicMock()
    mock.ainvoke = AsyncMock(return_value=MagicMock(lessons=[
        Lesson(category="technique_worked", body="ms17_010 worked",
               mitre_technique_id="T1210"),
    ]))
    return mock


@pytest.mark.asyncio
async def test_phase6_full_pipeline(
    tmp_path, monkeypatch, sandbox_roe_yaml, fixtures_dir
):
    """Mocked Phase 6 pipeline: full kill chain ending in report deliverables.

    Verifies the full Phase 6 graph runs end-to-end with all LLM +
    subprocess + subagent + EventBus boundaries mocked, and that the
    final state is populated with every Phase 6 deliverable field
    (report_paths, lessons, mitre_mappings, summary) PLUS the Phase
    1-5 carry-overs (hosts, footholds, local_users, harvested_secrets,
    persistence_artifacts, pivots, sub_engagements, cleanup_results,
    phase="done").
    """
    # Run inside tmp_path so engagements/ + logs/ + db/ never touch the repo.
    monkeypatch.chdir(tmp_path)
    setup_logging(log_dir=str(tmp_path / "logs"))

    # --- Register RoE ---------------------------------------------------
    roe = load_roe(sandbox_roe_yaml)
    # always_ask exercises the real EventBus HitL path (auto_approve
    # short-circuits the gate → the bus patches would be no-ops
    # assertion-wise). Matches Phase 3 / 4 / 5 T14.
    roe.hitl_mode = "always_ask"
    engagement_id = "p6-pipeline"
    register_roe(engagement_id, roe)
    init_engagement_folder(engagement_id, "192.168.56.22", "operator")

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
    # Pre-seeded foothold is Windows (access_type="winrm") → windowsenum
    # is dispatched for it; the exploit-phase Shellshock foothold (on
    # 10.10.10.56) is Linux → linuxenum is dispatched for it. Both are
    # mocked so both paths run deterministically.
    fake_user_linux = User(
        host_ip="10.10.10.56",
        username="www-data",
        uid="33",
        groups=["www-data"],
        is_admin=False,
        is_service_account=True,
    )
    fake_secret_linux = Secret(
        host_ip="10.10.10.56",
        secret_type="password",
        secret_value="toor",
        source="/etc/shadow",
    )
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
            users=[fake_user_linux],
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
        return_value=MagicMock(secrets=[fake_secret_linux])
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

    # --- Phase 5 sub-agent mock payloads -------------------------------
    # pivot_out: a successful wmiexec pass-the-hash onto the pivot
    # target. needs_tunnel=False so the TunnelSetup sub-agent isn't
    # invoked (still patched defensively below).
    pivot_out = PivotExecutorOutput(
        pivot=PivotRecord(
            target_host="192.168.56.11",
            method="wmiexec",
            credentials_used=["s-1"],
            success=True,
            needs_tunnel=False,
        ),
        success=True,
        output="goaad\\administrator",
    )

    # _fake_sub_state: a completed sub-engagement state. spawn_sub_eng-
    # agement is mocked to return this so the pipeline test doesn't
    # spawn a real nested graph (the spawner itself has its own
    # integration test in Task 10). phase="done" → status="completed"
    # in the resulting SubEngagementRef.
    def _fake_sub_state():
        sub = EngagementState(
            engagement_id="p6-pipeline_sub_01",
            target_scope=["192.168.56.11"],
            operator="operator",
            rules_of_engagement=roe,
        )
        sub.parent_engagement_id = engagement_id
        sub.phase = "done"
        sub.summary = "sub-engagement complete"
        return sub

    # remover_out / scanner_out: typed CleanupResult payloads for the
    # pre-seeded artifact a-1 on host 192.168.56.22. Both verified=True
    # because the pipeline-level assertion demands every cleanup result
    # verified (the sub-agent isolation tests in Tasks 8/9 cover the
    # verified=False failure path).
    remover_out = ArtifactRemoverOutput(
        results=[
            CleanupResult(
                artifact_id="a-1",
                host_ip="192.168.56.22",
                removal_command="schtasks /delete /tn AutoRedUpdate /f",
                success=True,
                verified=True,
            )
        ]
    )
    scanner_out = VerificationScannerOutput(
        results=[
            CleanupResult(
                artifact_id="a-1",
                host_ip="192.168.56.22",
                removal_command='schtasks /query /tn "AutoRedUpdate"',
                success=True,
                verified=True,
            )
        ]
    )

    # --- Build initial state (pre-seed Phase 5 fields) ------------------
    # LangGraph's reducer merges fields (state.X + new_X in each node),
    # so pre-seeding hosts / footholds / secrets / artifacts / evidence
    # gives the Lateral + Cleanup Agents enough state to exercise every
    # Phase 5 code path even though the Phase 1-3 mocks surface Lame
    # (single-host 10.10.10.5) recon + Shellshock foothold. The two
    # GoAD hosts are pre-seeded; the Lame host appends via the recon
    # merge → final state.hosts = [192.168.56.22, 192.168.56.11, 10.10.10.5].
    pre_seed_hosts = [
        Host(ip="192.168.56.22", hostname="srv02", os_guess="Windows Server 2019"),
        Host(ip="192.168.56.11", hostname="dc01", os_guess="Windows Server 2019"),
    ]
    # Two pre-seeded footholds: one on the GoAD primary (Windows, drives
    # the WindowsEnum mock branch in postex) and one on the Lame host
    # discovered by the recon mock (10.10.10.5 — matches the nmap
    # fixture's host). The 10.10.10.5 foothold keeps 10.10.10.5 OUT of
    # the Lateral Agent's target_hosts list (known host without a
    # foothold) so only the un-footholded GoAD pivot target
    # 192.168.56.11 remains — yielding exactly 1 pivot candidate and
    # exactly 1 sub-engagement, matching the assertion
    # ``len(sub_engagements) == 1``.
    pre_seed_footholds = [
        Foothold(
            id="f-1",
            host_ip="192.168.56.22",
            username="administrator",
            context="system",
            method="psexec_smb",
            access_type="winrm",
            evidence_path=f"engagements/{engagement_id}/evidence/foothold_f1.txt",
            established_at=datetime.utcnow(),
            hypothesis_rank=1,
        ),
        Foothold(
            id="f-2",
            host_ip="10.10.10.5",
            username="www-data",
            context="user",
            method="Shellshock (CVE-2014-6271)",
            access_type="shell",
            evidence_path=f"engagements/{engagement_id}/evidence/foothold_f2.txt",
            established_at=datetime.utcnow(),
            hypothesis_rank=1,
        ),
    ]
    pre_seed_secrets = [
        Secret(
            id="s-1",
            host_ip="192.168.56.22",
            secret_type="hash",
            secret_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            source="secretsdump:SAM/administrator",
        )
    ]
    pre_seed_artifacts = [
        PersistenceArtifact(
            id="a-1",
            host_ip="192.168.56.22",
            method="scheduled_task",
            details={
                "task_name": "AutoRedUpdate",
                "command": "powershell -enc x",
            },
            removal_command="schtasks /delete /tn AutoRedUpdate /f",
            foothold_id="f-1",
        )
    ]
    pre_seed_evidence_paths = ["linpeas_upload.sh"]

    bus = EventBus()
    state = EngagementState(
        engagement_id=engagement_id,
        target_scope=["192.168.56.22", "192.168.56.11"],
        operator="operator",
        rules_of_engagement=roe,
        hosts=pre_seed_hosts,
        footholds=pre_seed_footholds,
        harvested_secrets=pre_seed_secrets,
        persistence_artifacts=pre_seed_artifacts,
        evidence_paths=pre_seed_evidence_paths,
    )

    # --- Patch run_subprocess in every tool module ----------------------
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
        # _maybe_run_bloodhound is patched defensively — the
        # pre-seeded Windows foothold triggers it, but we don't want
        # any AD-cred lookup running inside the pipeline test.
        stack.enter_context(
            patch(
                "autored.agents.postex._maybe_run_bloodhound",
                new=AsyncMock(return_value=None),
            )
        )

        # --- Phase 5 lateral patches ----------------------------------
        # pivotexecutor_subagent: returns the successful wmiexec pivot.
        # Patched at the autored.agents.lateral.pivotexecutor_subagent
        # site (module-level re-import — same pattern as the postex
        # sub-agent patches).
        mock_pivot = MagicMock()
        mock_pivot.configure_mock(spec=pivotexecutor_subagent)
        mock_pivot.ainvoke = AsyncMock(return_value=pivot_out)
        stack.enter_context(
            patch(
                "autored.agents.lateral.pivotexecutor_subagent",
                new=mock_pivot,
            )
        )

        # tunnelsetup_subagent: defensive no-op (pivot.needs_tunnel=False
        # so this never fires). Patched for the same reason
        # _maybe_run_bloodhound is — catches future drift if the
        # helper is called unconditionally.
        mock_tunnel = MagicMock()
        mock_tunnel.configure_mock(spec=tunnelsetup_subagent)
        mock_tunnel.ainvoke = AsyncMock(return_value=MagicMock(tunnel=None))
        stack.enter_context(
            patch(
                "autored.agents.lateral.tunnelsetup_subagent",
                new=mock_tunnel,
            )
        )

        # spawn_sub_engagement: returns a fake completed sub-state so
        # the pipeline test doesn't nest a real Phase 4 graph. The
        # spawner itself has its own integration test in Task 10
        # (test_sub_engagement.py) which exercises the real recursion
        # path against a mocked sub-graph.
        stack.enter_context(
            patch(
                "autored.agents.lateral.spawn_sub_engagement",
                new=AsyncMock(return_value=_fake_sub_state()),
            )
        )

        # --- Phase 5 cleanup patches ----------------------------------
        # artifactremover_subagent / verificationscanner_subagent:
        # return typed CleanupResult payloads for the pre-seeded
        # artifact a-1 on host 192.168.56.22.
        mock_remover = MagicMock()
        mock_remover.configure_mock(spec=artifactremover_subagent)
        mock_remover.ainvoke = AsyncMock(return_value=remover_out)
        stack.enter_context(
            patch(
                "autored.agents.cleanup.artifactremover_subagent",
                new=mock_remover,
            )
        )

        mock_scanner = MagicMock()
        mock_scanner.configure_mock(spec=verificationscanner_subagent)
        mock_scanner.ainvoke = AsyncMock(return_value=scanner_out)
        stack.enter_context(
            patch(
                "autored.agents.cleanup.verificationscanner_subagent",
                new=mock_scanner,
            )
        )

        # cleanup.run_subprocess: defensive no-op (only called on
        # tunnel teardowns; the pivot doesn't need a tunnel so this
        # never fires). Patched for the same defensive reason as
        # tunnelsetup_subagent / _maybe_run_bloodhound.
        stack.enter_context(
            patch(
                "autored.agents.cleanup.run_subprocess",
                new=AsyncMock(
                    return_value=MagicMock(
                        stdout="",
                        stderr="",
                        returncode=0,
                        duration_sec=0.1,
                        command="pkill",
                    )
                ),
            )
        )

        # --- Phase 6 report layer patches -----------------------------
        # mitremapper / execsummarywriter / techreportwriter /
        # lessonextractor: the four Report Agent sub-agents (each
        # returns its typed payload — mappings / summary_markdown /
        # report_markdown / lessons). render_pdf returns None to
        # exercise the WeasyPrint-unavailable degradation branch.
        # persist_engagement_memory is patched so the cross-engagement
        # SQLite + Chroma writes never fire (their isolation is covered
        # by tests/unit/reporting/test_memory_writer.py).
        report_layer = {
            "autored.agents.report.mitremapper_subagent": _mitre_mock(),
            "autored.agents.report.execsummarywriter_subagent": _exec_mock(),
            "autored.agents.report.techreportwriter_subagent": _tech_mock(),
            "autored.agents.report.lessonextractor_subagent": _lesson_mock(),
            "autored.agents.report.render_pdf": AsyncMock(return_value=None),
            "autored.agents.report.persist_engagement_memory": AsyncMock(
                return_value=MagicMock(
                    findings_written=1,
                    db_error=None,
                    chroma_error=None,
                )),
        }
        for target, mock_obj in report_layer.items():
            stack.enter_context(patch(target, mock_obj))

        # --- EventBus patches (HitL gate approve path) -----------------
        # I1: the bus travels via RunnableConfig so patch the bus
        # object's methods here. The config built below carries this
        # same bus instance to exploit_node + postex_node +
        # lateral_node + cleanup_node — the patch applies wherever
        # the bus is referenced.
        #
        # The response envelope carries BOTH shapes the AutoRed
        # gates use:
        # - Exploit Agent + Post-Ex Agent gates consume
        #   ``{"response": "approve"|"reject"|"edit"|"skip", ...}``.
        # - Lateral Agent + Cleanup Agent gates consume
        #   ``{"approved": bool, ...}`` (no edit / skip affordance).
        # Returning both keys in one envelope keeps a single mock
        # satisfying every gate without needing per-call side_effect
        # dispatch — the gates only read the keys they care about.
        stack.enter_context(
            patch.object(
                bus,
                "wait_for_tui_response",
                new=AsyncMock(
                    return_value={
                        "response": "approve",
                        "modified_command": None,
                        "approved": True,
                    }
                ),
            )
        )
        stack.enter_context(
            patch.object(bus, "emit_to_tui", new=AsyncMock())
        )

        # --- Build and run Phase 6 graph -------------------------------
        # checkpointer=None keeps the test off the persistence layer
        # (asyncio.Queue handles inside the bus aren't msgpack-
        # serialisable).
        graph = build_phase6_graph(checkpointer=None)
        config = {
            "configurable": {
                "thread_id": engagement_id,
                "event_bus": bus,
            }
        }
        final_state = await graph.ainvoke(state, config=config)

    # --- Verify final state ---------------------------------------------
    # Phase 6 closes the chain — the Report Agent set phase="done".
    assert final_state["phase"] == "done", (
        f"Expected phase='done' (Report Agent ran); got "
        f"{final_state['phase']!r}"
    )

    # ---- Phase 6 deliverable assertions -------------------------------
    # report_paths is populated with markdown + lessons paths.
    assert final_state["report_paths"] is not None, (
        "Report Agent did not populate report_paths"
    )
    report_md = Path(final_state["report_paths"].markdown_path)
    lessons_json = Path(final_state["report_paths"].lessons_path)
    assert report_md.exists(), (
        f"report.md not written at {report_md}"
    )
    assert report_md.stat().st_size > 0, (
        f"report.md is empty at {report_md}"
    )
    assert lessons_json.exists(), (
        f"lessons.json not written at {lessons_json}"
    )

    # ≥1 lesson + ≥1 MITRE mapping + truthy summary.
    assert len(final_state["lessons"]) >= 1, (
        "Report Agent recorded no lessons (lessonextractor mock "
        "should have surfaced >=1 Lesson)"
    )
    assert len(final_state["mitre_mappings"]) >= 1, (
        "Report Agent recorded no mitre_mappings (mitremapper mock "
        "should have surfaced >=1 MitreMapping)"
    )
    assert final_state["summary"], (
        f"Expected non-empty summary; got {final_state['summary']!r}"
    )

    # ---- Phase 1-5 carry-overs (same as the Phase 5 pipeline test) ----
    # Pre-seeded 2 GoAD hosts + the Lame host from recon → ≥3 hosts.
    assert len(final_state["hosts"]) >= 2, (
        f"Expected >=2 hosts (pre-seed GoAD pair + Lame recon); got "
        f"{len(final_state['hosts'])}"
    )
    assert len(final_state["services"]) >= 1, "No services discovered"
    footholds = final_state["footholds"]
    assert len(footholds) >= 1, "Exploit Agent recorded no foothold"

    # local_users (linuxenum mock surfaced a www-data User on 10.10.10.56).
    local_users = final_state["local_users"]
    assert len(local_users) >= 1, (
        "Post-Ex Agent recorded no local_users (linuxenum_subagent "
        "should have surfaced >=1 User)"
    )

    # harvested_secrets (pre-seeded s-1 admin hash on 192.168.56.22 +
    # credharvester mock Secret on 10.10.10.56).
    harvested_secrets = final_state["harvested_secrets"]
    assert len(harvested_secrets) >= 1, (
        "Post-Ex Agent recorded no harvested_secrets"
    )

    # persistence_artifacts (pre-seeded a-1 on 192.168.56.22 +
    # persistenceagent mock artifact on 10.10.10.56).
    persistence_artifacts = final_state["persistence_artifacts"]
    assert len(persistence_artifacts) >= 1, (
        "Post-Ex Agent recorded no persistence_artifacts"
    )

    # ---- Phase 5 specific assertions --------------------------------
    # 1. Pivot onto the un-footholded GoAD host (192.168.56.11).
    pivots = final_state["pivots"]
    assert len(pivots) >= 1, "Lateral Agent recorded no pivot"
    assert pivots[0].target_host == "192.168.56.11", (
        f"Expected pivot target_host=192.168.56.11; got "
        f"{pivots[0].target_host!r}"
    )
    assert pivots[0].success is True, (
        f"Expected pivot success=True; got {pivots[0].success!r}"
    )

    # 2. Movement path from the foothold host to the pivot target.
    movement_paths = final_state["movement_paths"]
    assert len(movement_paths) >= 1, "No movement_paths recorded"

    # 3. Sub-engagement linked to parent (spec §13.5 ship criterion).
    sub_engagements = final_state["sub_engagements"]
    assert len(sub_engagements) == 1, (
        f"Expected exactly 1 sub-engagement; got "
        f"{len(sub_engagements)}"
    )
    ref = sub_engagements[0]
    assert ref.sub_id == "p6-pipeline_sub_01", (
        f"Expected sub_id=p6-pipeline_sub_01; got {ref.sub_id!r}"
    )
    assert ref.status == "completed", (
        f"Expected sub-engagement status=completed; got {ref.status!r}"
    )

    # 4. Cleanup removed + verified every artifact (spec §13.5).
    cleanup_results = final_state["cleanup_results"]
    assert len(cleanup_results) >= 2, (
        f"Expected >=2 cleanup_results (removal + verification); "
        f"got {len(cleanup_results)}"
    )
    assert all(r.verified for r in cleanup_results), (
        f"Expected all cleanup_results verified=True; got unverified: "
        f"{[r for r in cleanup_results if not r.verified]}"
    )

    # Clean up the engagement folder so repeated test runs don't
    # accumulate artifacts (defensive — tmp_path already isolates us,
    # but the Report Agent writes engagements/<id>/report.md and
    # lessons.json which we want gone before the next run).
    shutil.rmtree(Path("engagements") / engagement_id, ignore_errors=True)
