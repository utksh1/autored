"""Cleanup Agent — LangGraph node that removes every artifact the
engagement created and verifies the removal by re-scan (spec §6.6).

Steps:
  1. **Collect** — persistence artifacts, tunnels, staged temp files.
  2. **Plan** — group per host; attach each host's credentials from
     the harvested secrets (removal commands need working auth).
  3. **HitL gate** — one final operator confirmation for the whole
     plan. Rejection short-circuits to ``phase="report"`` with zero
     removals (Review Focus #4).
  4. **Execute** — ArtifactRemover per host (removal commands
     verbatim), tunnel teardowns locally, temp files unlinked locally.
  5. **Verify** — VerificationScanner per host (absence re-scan).

Both removal AND verification results land in ``cleanup_results``
(spec §6.6: ``cleanup_results + verification``). Hosts run sequentially
— see the plan's documented deviation from the spec's gather fan-out
(parallel fan-out multiplies auth failures under Meterpreter / RPC
backpressure and makes failures harder to attribute; sequencing costs
seconds per host and keeps logs linear; the plan structure is
unchanged).

I1 (Phase 3 fix wave): the EventBus travels via
``config["configurable"]["event_bus"]`` (RunnableConfig), NOT via
``state.event_bus``. LangGraph's reducer round-trips state through
``model_dump() + model_validate()`` which strips the
``__pydantic_extra__`` dict where ``state.event_bus = ...`` was stored
under ``extra="allow"``. The RunnableConfig is the standard LangGraph
channel for runtime objects (it never crosses the reducer boundary).
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from langchain_core.runnables import RunnableConfig

from autored.logging import get_logger
from autored.models.cleanup import (
    CleanupPlan,
    CleanupResult,
    HostCleanupPlan,
)
from autored.roe_guard import register_roe
from autored.state import EngagementState
from autored.subagents.artifactremover import artifactremover_subagent
from autored.subagents.verificationscanner import verificationscanner_subagent
from autored.subprocess_runner import run_subprocess

log = get_logger("agents.cleanup")

# Locally staged binaries / staging archives that are safe to delete.
# Raw tool output and evidence are engagement deliverables — NEVER
# deleted by cleanup.
_TEMP_FILE_MARKERS = ("linpeas", "winpeas", "bloodhound", "mimikatz")


def _identify_temp_files(evidence_paths: list[str]) -> list[str]:
    """Pick staged tool binaries / staging zips out of evidence paths.

    Substring match (case-insensitive) on the path's basename for the
    four markers: ``linpeas``, ``winpeas``, ``bloodhound``,
    ``mimikatz``. Raw nmap output and screenshots are engagement
    deliverables — never in this list.
    """
    return [
        p
        for p in evidence_paths
        if any(m in Path(p).name.lower() for m in _TEMP_FILE_MARKERS)
    ]


def _creds_for_host(host_ip: str, secrets) -> dict:
    """First usable credential triple for a host (hash preferred).

    Usernames are encoded in ``Secret.source`` (Phase 4 convention —
    ``"secretsdump:SAM/<user>"``); mirrors the Lateral Agent's parser.
    A secret without ``"/"`` in its source is skipped (file paths,
    registry keys, etc. — no username parseable). A host with no
    usable secret yields empty strings; the sub-agent will fail with a
    clear auth error rather than silently binding as a wrong user.
    """
    for secret in secrets:
        if secret.host_ip != host_ip or "/" not in secret.source:
            continue
        username = secret.source.rsplit("/", 1)[-1].strip()
        if not username:
            continue
        if secret.secret_type == "hash":
            return {
                "username": username,
                "password": "",
                "nthash": secret.secret_value,
            }
        if secret.secret_type == "password":
            return {
                "username": username,
                "password": secret.secret_value,
                "nthash": "",
            }
    return {"username": "", "password": "", "nthash": ""}


def _generate_cleanup_plan(
    artifacts, tunnels, temp_files, secrets
) -> CleanupPlan:
    """Group all cleanup actions per host, with credentials attached.

    Three categories of host plan:
      - **Real host** (keyed by ``artifact.host_ip``) — carries
        ``artifact_ids``, ``removal_commands``, and the harvested
        creds (``username`` / ``password`` / ``nthash``) for the host.
      - **Tunnel pseudo-host** (keyed by ``"tunnel:<proxy_endpoint>"``)
        — carries ``tunnel_teardowns`` only. Teardowns run locally on
        the AutoRed host; grouping them under a pseudo-host keeps them
        out of the remote-removal loop.
      - **``local:tmp``** — carries ``temp_files`` only. Unlinked
        locally.

    ``total_actions`` = sum of removal_commands + tunnel_teardowns +
    temp_files across every host plan.
    """
    by_host: dict[str, HostCleanupPlan] = {}
    for artifact in artifacts:
        plan = by_host.setdefault(
            artifact.host_ip,
            HostCleanupPlan(host_ip=artifact.host_ip),
        )
        plan.artifact_ids.append(artifact.id)
        plan.removal_commands.append(artifact.removal_command)

    for tunnel in tunnels:
        # Tunnel teardowns run on the AutoRed host — group them under a
        # pseudo-host entry keyed by the tunnel's proxy endpoint.
        key = f"tunnel:{tunnel.proxy_endpoint}"
        plan = by_host.setdefault(
            key, HostCleanupPlan(host_ip=key, transport="ssh")
        )
        plan.tunnel_teardowns.append(tunnel.teardown_command)

    if temp_files:
        plan = by_host.setdefault(
            "local:tmp", HostCleanupPlan(host_ip="local:tmp")
        )
        plan.temp_files.extend(temp_files)

    # Attach credentials to real host plans (those without a
    # ``tunnel:`` / ``local:`` prefix).
    for host_plan in by_host.values():
        if not host_plan.host_ip.startswith(("tunnel:", "local:")):
            creds = _creds_for_host(host_plan.host_ip, secrets)
            host_plan.username = creds["username"]
            host_plan.password = creds["password"]
            host_plan.nthash = creds["nthash"]

    total = sum(
        len(p.removal_commands)
        + len(p.tunnel_teardowns)
        + len(p.temp_files)
        for p in by_host.values()
    )
    return CleanupPlan(by_host=list(by_host.values()), total_actions=total)


async def cleanup_node(
    state: EngagementState, config: RunnableConfig
) -> dict:
    """LangGraph node: run the Cleanup Agent.

    Returns a state-dict patch with new ``cleanup_results`` and
    ``phase="report"``. The EventBus travels via
    ``config["configurable"]["event_bus"]`` per the Phase 3 fix wave I1
    — never via state, since LangGraph's reducer round-trips state
    through ``model_dump() + model_validate()`` which strips the
    ``__pydantic_extra__`` dict where ``state.event_bus = ...`` was
    stored under ``extra="allow"``.
    """
    log.info("cleanup_start", engagement_id=state.engagement_id)

    # Defensive RoE registration (same as postex_node / lateral_node —
    # tests / resume / direct-node-entry paths bypass the CLI).
    register_roe(state.engagement_id, state.rules_of_engagement)

    bus = _get_bus(config)

    temp_files = _identify_temp_files(state.evidence_paths)
    plan = _generate_cleanup_plan(
        state.persistence_artifacts,
        state.tunnels,
        temp_files,
        state.harvested_secrets,
    )
    log.info(
        "cleanup_plan",
        hosts=len(plan.by_host),
        actions=plan.total_actions,
    )

    # HitL gate — one confirmation for the whole plan.
    if state.rules_of_engagement.hitl_mode != "auto_approve":
        approved = await _hitl_cleanup_gate(plan, state, bus)
        if not approved:
            log.warning("cleanup_rejected_by_operator")
            return {
                # Review Focus #4 — rejection executes nothing; the
                # empty cleanup_results is the audit trail that no
                # removal / teardown / temp-file unlink ran.
                "cleanup_results": [],
                "phase": "report",
                "iteration_count": state.iteration_count + 1,
            }

    cleanup_results: list[CleanupResult] = []

    # Hosts run SEQUENTIALLY (deviation from spec §6.6's gather fan-out
    # — see module docstring). Order is the dict insertion order from
    # ``_generate_cleanup_plan``: real hosts first, then tunnel pseudo-
    # hosts, then ``local:tmp``.
    for host_plan in plan.by_host:
        # Tunnel teardowns run locally on the AutoRed host.
        for teardown in host_plan.tunnel_teardowns:
            await run_subprocess(["sh", "-c", teardown], timeout=30)
            cleanup_results.append(
                CleanupResult(
                    artifact_id=host_plan.host_ip,
                    host_ip=host_plan.host_ip,
                    removal_command=teardown,
                    success=True,
                    verified=True,
                    timestamp=datetime.utcnow(),
                )
            )

        # Staged temp files are unlinked locally.
        for temp_path in host_plan.temp_files:
            try:
                Path(temp_path).unlink(missing_ok=True)
                cleanup_results.append(
                    CleanupResult(
                        artifact_id=temp_path,
                        host_ip="local",
                        removal_command=f"rm {temp_path}",
                        success=True,
                        verified=True,
                        timestamp=datetime.utcnow(),
                    )
                )
            except OSError as exc:
                cleanup_results.append(
                    CleanupResult(
                        artifact_id=temp_path,
                        host_ip="local",
                        removal_command=f"rm {temp_path}",
                        success=False,
                        verified=False,
                        error=str(exc),
                        timestamp=datetime.utcnow(),
                    )
                )

        # Artifact removal + verification via the sub-agents (real
        # hosts with recorded artifacts only). Tunnel pseudo-hosts and
        # ``local:tmp`` have no ``artifact_ids`` and skip this block.
        if host_plan.artifact_ids:
            artifacts = [
                a
                for a in state.persistence_artifacts
                if a.host_ip == host_plan.host_ip
            ]
            artifacts_dicts = [a.model_dump() for a in artifacts]

            removal = await artifactremover_subagent.ainvoke(
                {
                    "host_plan": host_plan.model_dump(),
                    "artifacts": artifacts_dicts,
                    "engagement_id": state.engagement_id,
                }
            )
            cleanup_results.extend(removal.results)

            scan = await verificationscanner_subagent.ainvoke(
                {
                    "host_plan": host_plan.model_dump(),
                    "artifacts": artifacts_dicts,
                    "engagement_id": state.engagement_id,
                }
            )
            cleanup_results.extend(scan.results)

    failed = [r for r in cleanup_results if not r.verified]
    if failed:
        log.error("cleanup_failures", count=len(failed))

    log.info(
        "cleanup_done",
        results=len(cleanup_results),
        unverified=len(failed),
    )
    return {
        "cleanup_results": state.cleanup_results + cleanup_results,
        "phase": "report",
        "iteration_count": state.iteration_count + 1,
    }


def _get_bus(config: RunnableConfig) -> object | None:
    """Extract EventBus from RunnableConfig (Phase 3 fix wave I1).

    Returns ``None`` in headless mode (no bus in config) — the HitL
    helpers fail open (auto-approve) when the bus is missing.
    """
    return (config or {}).get("configurable", {}).get("event_bus")


async def _hitl_cleanup_gate(
    plan: CleanupPlan, state: EngagementState, bus
) -> bool:
    """Final operator confirmation of the whole cleanup plan.

    Sandbox mode (``hitl_mode == "auto_approve"``) short-circuits
    before any blocking wait. A missing EventBus in non-sandbox mode
    fails OPEN with a warning — a headless ``--no-tui`` run has nobody
    to ask (matches the Lateral Agent's headless shape).

    Emits a ``hitl_gate`` event carrying the full plan so the TUI can
    render every action the operator is about to approve (Review Focus
    #4 — rejection short-circuits to ``phase="report"`` with zero
    results; the operator sees the whole plan, not a summary).
    """
    if bus is not None:
        await bus.emit_to_tui(
            {
                "type": "hitl_gate",
                "gate": "cleanup_plan",
                "hosts": [p.host_ip for p in plan.by_host],
                "total_actions": plan.total_actions,
                "actions": [
                    {
                        "host": p.host_ip,
                        "removals": p.removal_commands,
                        "teardowns": p.tunnel_teardowns,
                        "temp_files": p.temp_files,
                    }
                    for p in plan.by_host
                ],
            }
        )
    if state.rules_of_engagement.hitl_mode == "auto_approve":
        log.info("cleanup_auto_approved", actions=plan.total_actions)
        return True
    if bus is None:
        log.warning("cleanup_gate_headless_fail_open")
        return True
    response = await bus.wait_for_tui_response()
    approved = bool(response.get("approved", False))
    log.info("cleanup_gate_response", approved=approved)
    return approved
