"""AutoRed Post-Ex Agent — LangGraph node (Phase 4, Task 11).

Drives Phase 4 from a verified foothold (Phase 3 output) through the
six post-exploitation sub-activities:

1. **Enumeration** — runs ``linuxenum_subagent`` or
   ``windowsenum_subagent`` (per ``_determine_os_type``) plus
   ``credharvester_subagent`` to surface local users, harvested
   secrets, trust relationships, and privesc candidates. Always runs —
   no gate.
2. **BloodHound** (Windows-only) — ``_maybe_run_bloodhound`` logs intent
   but does NOT call ``bloodhound_collect.ainvoke`` in Phase 4 (the
   helper needs harvested AD credentials, which Phase 4 hasn't chained
   yet — Phase 5 wires the actual call).
3. **Privesc** — iterates candidates. RoE check for the ``kernel``
   category (blocks if ``kernel_exploits_allowed=False`` — RF#2). HitL
   gate for ``app_system`` and ``kernel`` categories
   (``hitl_required=True``); ``misconfig`` is auto-attempted
   (``auto_attempt=True``). RF#5: a rejected candidate falls through
   to the next.
4. **Persistence** (RF#1) — SKIPPED ENTIRELY if
   ``persistence_allowed=False``. The check lives at the
   ``postex_node`` level, not inside the helper — RoE is a hard block,
   HitL is a soft gate.
5. **Evasion** — SKIPPED if ``evasion_allowed=False``.
6. **Exfiltration** — SKIPPED if ``exfiltration_allowed=False``.

I1 (Phase 3 fix wave): the EventBus travels via
``config["configurable"]["event_bus"]`` (RunnableConfig), NOT via
``state.event_bus``. LangGraph's reducer round-trips state through
``model_dump() + model_validate()`` which strips the
``__pydantic_extra__`` dict where ``state.event_bus = ...`` was stored
under ``extra="allow"``. The RunnableConfig is the standard LangGraph
channel for runtime objects (it never crosses the reducer boundary).
"""
from __future__ import annotations

import os

from langchain_core.runnables import RunnableConfig

from autored.foothold_session import foothold_session_context
from autored.logging import get_logger
from autored.models.postex import (
    EvasionAction,
    ExfilEvidence,
    PersistenceArtifact,
    PrivescAttempt,
    PrivescCandidate,
    Secret,
    User,
)
from autored.state import EngagementState
from autored.subagents.credharvester import credharvester_subagent
from autored.subagents.evasionagent import evasionagent_subagent
from autored.subagents.exfilagent import exfilagent_subagent
from autored.subagents.linuxenum import linuxenum_subagent
from autored.subagents.persistenceagent import persistenceagent_subagent
from autored.subagents.privescfinder import privescfinder_subagent
from autored.subagents.windowsenum import windowsenum_subagent
from autored.tools.bloodhound import (
    bloodhound_collect,  # noqa: F401  (re-exported so test patches `autored.agents.postex.bloodhound_collect` can verify non-invocation)
)

log = get_logger("agents.postex")


# Hard-coded risk categories — drives the RoE / HitL dispatch for each
# privesc candidate. ``auto_attempt=True`` means the candidate is
# attempted without a HitL gate (misconfig is low-risk and almost
# always reversible). ``hitl_required=True`` means the operator must
# approve before the attempt fires. ``roe_key`` is the
# RulesOfEngagement field that gates this category — ``None`` means no
# RoE block; the candidate flows through to the HitL gate.
PRIVESC_RISK_CATEGORIES: dict[str, dict[str, object]] = {
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


async def postex_node(
    state: EngagementState, config: RunnableConfig
) -> dict:
    """LangGraph node: runs the Post-Ex Agent.

    Iterates ``state.footholds`` and runs the six sub-activities per
    foothold. Returns a state-shaped dict that advances the engagement
    to ``phase=lateral`` (Phase 5 lateral-movement agent inherits the
    populated post-ex collections).

    The EventBus is pulled from
    ``config["configurable"]["event_bus"]`` per the Phase 3 I1 fix —
    the bus is a non-state runtime object and the RunnableConfig is
    the standard LangGraph channel for those.
    """
    log.info("postex_start", engagement_id=state.engagement_id)

    all_users: list[User] = []
    all_secrets: list[Secret] = []
    all_trusts: list = []
    all_privesc_candidates: list[PrivescCandidate] = []
    all_privesc_attempts: list[PrivescAttempt] = []
    all_persistence_artifacts: list[PersistenceArtifact] = []
    all_evasion_actions: list[EvasionAction] = []
    all_exfil_proofs: list[ExfilEvidence] = []

    # Phase 6: install the foothold session manager so the enum/cred-harvest
    # wrappers (linpeas/winpeas/mimikatz) execute on live footholds via
    # the Phase 5 transport layer (sshpass for SSH, impacket_wmiexec for
    # winrm/rpc). Wrappers fall through to Phase 4 evidence-string mode
    # when no transport exists for a foothold's access_type. The context
    # manager guarantees the manager is uninstalled even on exceptions
    # so a later engagement doesn't inherit a stale session.
    with foothold_session_context(state):
        for foothold in state.footholds:
            os_type = _determine_os_type(foothold)
            log.info("postex_foothold", host=foothold.host_ip, os=os_type)

            # Sub-activity 1: Enumeration (always runs — no gate).
            enum_results = await _run_enumeration(
                foothold, os_type, state, config
            )
            all_users.extend(enum_results.get("users", []))
            all_secrets.extend(enum_results.get("secrets", []))
            all_trusts.extend(enum_results.get("trusts", []))
            all_privesc_candidates.extend(
                enum_results.get("privesc_candidates", [])
            )

            # Sub-activity 2: BloodHound (Windows-only, no HitL gate).
            if os_type == "windows":
                await _maybe_run_bloodhound(foothold, state, config)

            # Sub-activity 3: Privesc (RoE check + HitL gate per candidate).
            privesc_results = await _run_privesc(
                foothold,
                enum_results.get("privesc_candidates", []),
                state,
                config,
            )
            all_privesc_attempts.extend(privesc_results.get("attempts", []))
            all_secrets.extend(privesc_results.get("secrets", []))

            # Sub-activity 4: Persistence (RF#1 — RoE flag short-circuits
            # the WHOLE sub-activity, not just the gate).
            if state.rules_of_engagement.persistence_allowed:
                persist_results = await _run_persistence(
                    foothold, os_type, state, config
                )
                all_persistence_artifacts.extend(
                    persist_results.get("artifacts", [])
                )

            # Sub-activity 5: Evasion (RoE flag short-circuits).
            if state.rules_of_engagement.evasion_allowed:
                evasion_results = await _run_evasion(
                    foothold, state, config
                )
                all_evasion_actions.extend(
                    evasion_results.get("actions", [])
                )

            # Sub-activity 6: Exfiltration (RoE flag short-circuits).
            if state.rules_of_engagement.exfiltration_allowed:
                exfil_results = await _run_exfiltration(
                    foothold, state, config
                )
                all_exfil_proofs.extend(exfil_results.get("proofs", []))

    return {
        "local_users": state.local_users + all_users,
        "harvested_secrets": state.harvested_secrets + all_secrets,
        "trust_relationships": state.trust_relationships + all_trusts,
        "privesc_candidates": state.privesc_candidates
        + all_privesc_candidates,
        "privesc_attempts": state.privesc_attempts
        + all_privesc_attempts,
        "persistence_artifacts": state.persistence_artifacts
        + all_persistence_artifacts,
        "evasion_actions": state.evasion_actions + all_evasion_actions,
        "exfiltration_proof": state.exfiltration_proof
        + all_exfil_proofs,
        "phase": "lateral",
        "iteration_count": state.iteration_count + 1,
    }


def _get_bus(config: RunnableConfig) -> object | None:
    """Extract EventBus from RunnableConfig (Phase 3 fix wave I1).

    The bus is a runtime object that travels via
    ``config["configurable"]["event_bus"]`` — never via state, since
    LangGraph's reducer round-trips state through ``model_dump() +
    model_validate()`` which strips the ``__pydantic_extra__`` dict
    where ``state.event_bus = ...`` was stored under ``extra="allow"``.

    Returns ``None`` in headless mode (no bus in config) — the HitL
    helpers fail open (auto-approve) when the bus is missing.
    """
    return (config or {}).get("configurable", {}).get("event_bus")


def _determine_os_type(foothold) -> str:
    """Determine OS type from foothold access_type + method.

    Returns ``"linux"`` if ``access_type`` is ``ssh`` or ``shell`` AND
    the foothold's ``method`` does NOT contain ``"win"`` (case-
    insensitive). Otherwise returns ``"windows"``.

    The ``"win"`` substring check disambiguates Windows-shell footholds
    (e.g., ``method="winrm_smb"``) from Linux-shell footholds. ``ssh``
    access is unambiguously Linux for the purposes of post-ex
    dispatch (LinuxEnum runs linpeas, WindowsEnum runs winpeas).
    """
    if (
        foothold.access_type in ("ssh", "shell")
        and "win" not in foothold.method.lower()
    ):
        return "linux"
    return "windows"


async def _run_enumeration(
    foothold,
    os_type: str,
    state: EngagementState,
    config: RunnableConfig,
) -> dict:
    """Run enumeration sub-agent based on OS type, plus credharvester.

    Dispatches to ``linuxenum_subagent`` or ``windowsenum_subagent``
    per ``os_type`` to surface local users, secrets, and privesc
    candidates. Then runs ``credharvester_subagent`` to harvest any
    credentials the enum pass missed (mimikatz on Windows; deferred to
    Phase 5 on Linux/AD).

    Returns a dict with keys ``users``, ``secrets``, ``trusts``,
    ``privesc_candidates``. ``trusts`` is empty in Phase 4 — the enum
    sub-agents don't surface trust relationships yet (Phase 5 derives
    them from BloodHound output).
    """
    invoke_args = {
        "foothold_id": foothold.id,
        "host_ip": foothold.host_ip,
        "engagement_id": state.engagement_id,
    }
    if os_type == "linux":
        enum_result = await linuxenum_subagent.ainvoke(invoke_args)
    else:
        enum_result = await windowsenum_subagent.ainvoke(invoke_args)

    cred_result = await credharvester_subagent.ainvoke(
        {
            "foothold_id": foothold.id,
            "host_ip": foothold.host_ip,
            "os_type": os_type,
            "engagement_id": state.engagement_id,
        }
    )

    return {
        "users": _extract_field(enum_result, "users", []),
        "secrets": _extract_field(enum_result, "secrets", [])
        + _extract_field(cred_result, "secrets", []),
        "trusts": _extract_field(enum_result, "trusts", []),
        "privesc_candidates": _extract_field(
            enum_result, "privesc_candidates", []
        ),
    }


async def _maybe_run_bloodhound(
    foothold, state: EngagementState, config: RunnableConfig
) -> None:
    """Run BloodHound if AD credentials are available (Windows-only).

    Caller has already checked ``os_type == "windows"`` — this helper
    is invoked from the main loop's Windows branch only.

    I3 fix (Phase 4 fix wave): previously this helper only logged
    intent and deferred the actual ``bloodhound_collect.ainvoke`` call
    to Phase 5. The call is now wired in:

    * AD credentials: harvested secrets whose ``secret_type ==
      "password"`` (mimikatz plaintext).
    * Domain: looked up in ``state.trust_relationships`` for a trust
      with ``trust_type == "ad_domain"``. In Phase 4 the enum sub-
      agents don't surface trust relationships yet, so the call still
      won't fire during Phase 4 runs (Phase 5 populates trusts from
      BloodHound output). When Phase 5 populates trusts, this wiring
      is what makes BloodHound actually run.
    * Username: extracted from the secret's ``source`` field for
      mimikatz-harvested creds (format ``mimikatz:<provider>/<user>``);
      left empty for other source formats so the underlying
      ``bloodhound-python`` subprocess fails with a clear auth error
      rather than silently binding as a wrong user.
    * Failure: wrapped in try/except so a BloodHound subprocess error
      doesn't crash the postex_node loop — the failure is logged as
      ``postex_bloodhound_failed`` and the loop continues to the next
      sub-activity.

    Imports ``bloodhound_collect`` at module level so test patches
    like ``patch("autored.agents.postex.bloodhound_collect")`` can
    verify call/no-call (RF#4 — Linux footholds never invoke the
    helper; Windows footholds with no creds / no domain skip it).
    """
    ad_creds = [
        s for s in state.harvested_secrets if s.secret_type == "password"
    ]
    if not ad_creds:
        log.info(
            "postex_bloodhound_skipped_no_creds",
            host=foothold.host_ip,
        )
        return

    # Phase 4 enum sub-agents don't surface trust relationships yet —
    # ``trusts`` is empty until Phase 5 derives them from BloodHound
    # output. We look it up here anyway so Phase 5 doesn't have to
    # rewire the helper.
    domain = ""
    for t in state.trust_relationships:
        if t.trust_type == "ad_domain" and t.target:
            domain = t.target
            break
    if not domain:
        log.info(
            "postex_bloodhound_skipped_no_domain",
            host=foothold.host_ip,
        )
        return

    cred = ad_creds[0]
    # Mimikatz sources follow the format ``mimikatz:<provider>/<user>`` —
    # the username is the part after the last "/". For other source
    # formats (e.g., ``/etc/shadow``) we leave the username empty
    # rather than extract a nonsense value.
    username = ""
    if cred.source.startswith("mimikatz:") and "/" in cred.source:
        username = cred.source.rsplit("/", 1)[-1]

    log.info(
        "postex_bloodhound_intent",
        host=foothold.host_ip,
        cred_count=len(ad_creds),
        domain=domain,
        username=username,
    )
    try:
        await bloodhound_collect.ainvoke(
            {
                "username": username,
                "password": cred.secret_value,
                "domain": domain,
                "host": foothold.host_ip,
                "engagement_id": state.engagement_id,
            }
        )
        log.info(
            "postex_bloodhound_done",
            host=foothold.host_ip,
            domain=domain,
        )
    except Exception as e:
        log.error(
            "postex_bloodhound_failed",
            host=foothold.host_ip,
            domain=domain,
            error=str(e),
        )


async def _run_privesc(
    foothold,
    candidates: list,
    state: EngagementState,
    config: RunnableConfig,
) -> dict:
    """Run privesc sub-agent with RoE + HitL gates per candidate.

    If ``candidates`` is empty (the enum sub-agent didn't surface any),
    calls ``privescfinder_subagent.ainvoke`` to ask the LLM to identify
    candidates from the enum output.

    For each candidate, look up the risk category in
    ``PRIVESC_RISK_CATEGORIES``:
    - RoE check (``roe_key``) — if the RoE flag is False, the candidate
      is hard-blocked (RF#2: ``kernel_exploits_allowed=False`` blocks
      kernel candidates).
    - HitL gate (``hitl_required``) — if True and hitl_mode !=
      ``auto_approve``, emit a ``hitl_gate`` event and block on
      ``bus.wait_for_tui_response()``. Reject → try next candidate
      (RF#5). ``auto_attempt=True`` (misconfig) skips the gate.

    Records a ``PrivescAttempt`` for each candidate that survives both
    gates. Stops after the first successful attempt (don't pile on
    multiple privescs on the same foothold).
    """
    if not candidates:
        enum_results = [
            {
                "host_ip": foothold.host_ip,
                "os_type": _determine_os_type(foothold),
            }
        ]
        privesc_result = await privescfinder_subagent.ainvoke(
            {
                "enum_results": enum_results,
                "engagement_id": state.engagement_id,
            }
        )
        candidates = _extract_field(privesc_result, "candidates", [])

    attempts: list[PrivescAttempt] = []
    secrets: list[Secret] = []

    for candidate in candidates:
        risk_cfg = PRIVESC_RISK_CATEGORIES.get(
            candidate.category, PRIVESC_RISK_CATEGORIES["misconfig"]
        )

        # RoE hard-block (e.g., kernel_exploits_allowed=False).
        roe_key = risk_cfg["roe_key"]
        if roe_key and not getattr(state.rules_of_engagement, roe_key):
            log.info(
                "privesc_skipped_by_roe",
                technique=candidate.technique,
                roe_key=roe_key,
            )
            continue

        # HitL soft-gate (app_system / kernel categories — not misconfig).
        if (
            risk_cfg["hitl_required"]
            and state.rules_of_engagement.hitl_mode != "auto_approve"
        ):
            approved = await _hitl_privesc_gate(
                candidate, risk_cfg["risk"], config
            )
            if not approved:
                log.info(
                    "privesc_rejected_by_hitl",
                    technique=candidate.technique,
                )
                continue

        # Candidate survived RoE + HitL — record the attempt.
        attempt = PrivescAttempt(
            # I5 fix: use the candidate's stable UUID, not the foothold
            # host_ip. Two distinct candidates on the same host now
            # produce two distinct attempts (previously they collapsed
            # into one record because host_ip was used as the id).
            candidate_id=candidate.id,
            host_ip=foothold.host_ip,
            success=False,  # Phase 4 stub — Phase 6 replays and updates
            new_context=None,
        )
        attempts.append(attempt)
        if attempt.success:
            break  # don't try more once elevated

    return {"attempts": attempts, "secrets": secrets}


async def _hitl_privesc_gate(
    candidate: PrivescCandidate,
    risk: str,
    config: RunnableConfig,
) -> bool:
    """Emit HitL gate for a privesc candidate, wait for operator approval.

    Behaviour matrix:
    - ``bus is None`` (headless): fail open with a warning, return
      ``True`` — matches the Phase 3 ``exploit._hitl_gate`` pattern.
    - Otherwise: emit a ``hitl_gate`` event, then block on
      ``bus.wait_for_tui_response()``. ``response == "approve"`` →
      ``True``; anything else → ``False`` (the caller skips to the
      next candidate — RF#5).
    """
    bus = _get_bus(config)
    if bus is None:
        log.warning(
            "privesc_hitl_no_event_bus_fail_open",
            technique=candidate.technique,
        )
        return True
    await bus.emit_to_tui(
        {
            "type": "hitl_gate",
            "gate_type": "privesc",
            "technique": candidate.technique,
            "risk": risk,
            "command": candidate.exploit_command,
        }
    )
    response = await bus.wait_for_tui_response()
    return response.get("response") == "approve"


async def _run_persistence(
    foothold,
    os_type: str,
    state: EngagementState,
    config: RunnableConfig,
) -> dict:
    """Run persistence sub-agent (HitL gate if not auto_approve).

    Caller has already checked ``persistence_allowed`` (RF#1 — the RoE
    flag short-circuits the WHOLE sub-activity at the postex_node
    level, so this helper is only invoked when persistence is
    permitted by RoE).
    """
    bus = _get_bus(config)
    if (
        bus is not None
        and state.rules_of_engagement.hitl_mode != "auto_approve"
    ):
        await bus.emit_to_tui(
            {
                "type": "hitl_gate",
                "gate_type": "persistence",
                "host": foothold.host_ip,
                "os_type": os_type,
            }
        )
        response = await bus.wait_for_tui_response()
        if response.get("response") != "approve":
            log.info(
                "persistence_rejected_by_hitl",
                host=foothold.host_ip,
            )
            return {"artifacts": []}

    result = await persistenceagent_subagent.ainvoke(
        {
            "foothold": {
                "host_ip": foothold.host_ip,
                "id": foothold.id,
                "access_type": foothold.access_type,
            },
            "os_type": os_type,
            "engagement_id": state.engagement_id,
        }
    )
    return {"artifacts": _extract_field(result, "artifacts", [])}


async def _run_evasion(
    foothold,
    state: EngagementState,
    config: RunnableConfig,
) -> dict:
    """Run evasion sub-agent (HitL gate if not auto_approve).

    Caller has already checked ``evasion_allowed`` — the RoE flag
    short-circuits the whole sub-activity at the postex_node level.
    """
    bus = _get_bus(config)
    if (
        bus is not None
        and state.rules_of_engagement.hitl_mode != "auto_approve"
    ):
        await bus.emit_to_tui(
            {
                "type": "hitl_gate",
                "gate_type": "evasion",
                "host": foothold.host_ip,
            }
        )
        response = await bus.wait_for_tui_response()
        if response.get("response") != "approve":
            log.info(
                "evasion_rejected_by_hitl",
                host=foothold.host_ip,
            )
            return {"actions": []}

    result = await evasionagent_subagent.ainvoke(
        {
            "foothold_id": foothold.id,
            "host_ip": foothold.host_ip,
            "engagement_id": state.engagement_id,
        }
    )
    return {"actions": _extract_field(result, "actions", [])}


async def _run_exfiltration(
    foothold,
    state: EngagementState,
    config: RunnableConfig,
) -> dict:
    """Run exfil sub-agent (HitL gate if not auto_approve).

    Caller has already checked ``exfiltration_allowed`` — the RoE flag
    short-circuits the whole sub-activity at the postex_node level.

    Unwraps the ``ExfilAgentOutput.evidence`` field (singular — the
    sub-agent returns a single ExfilEvidence) into the ``proofs`` list
    (plural) the postex_node loop expects.

    C1 fix: ``exfilagent_subagent`` requires ``file_path`` and
    ``catch_server`` (it wraps ``exfil_https`` / ``exfil_dns`` which
    both need a target file and a destination). The previous call
    omitted both, which would crash with ``ValidationError`` the moment
    exfiltration actually ran (the integration tests masked this because
    ``MagicMock()`` without ``spec=`` accepts any kwargs). We now pass:

    * ``file_path`` — the first entry in ``state.evidence_paths`` if
      any, else a sensible default under the engagement's evidence
      folder.
    * ``catch_server`` — ``$CATCH_SERVER_URL`` (the env var documented
      in ``.env.example``), defaulting to ``http://localhost:8888``.

    Both defaults are safe-fail: if the operator hasn't populated
    ``evidence_paths`` or set the env var, the sub-agent still gets
    a syntactically valid call shape and can return a clear error from
    the underlying ``exfil_https`` / ``exfil_dns`` tool.
    """
    bus = _get_bus(config)
    if (
        bus is not None
        and state.rules_of_engagement.hitl_mode != "auto_approve"
    ):
        await bus.emit_to_tui(
            {
                "type": "hitl_gate",
                "gate_type": "exfil",
                "host": foothold.host_ip,
            }
        )
        response = await bus.wait_for_tui_response()
        if response.get("response") != "approve":
            log.info(
                "exfil_rejected_by_hitl",
                host=foothold.host_ip,
            )
            return {"proofs": []}

    file_path = (
        state.evidence_paths[0]
        if state.evidence_paths
        else f"engagements/{state.engagement_id}/evidence/exfil_target.txt"
    )
    catch_server = os.environ.get(
        "CATCH_SERVER_URL", "http://localhost:8888"
    )
    result = await exfilagent_subagent.ainvoke(
        {
            "host_ip": foothold.host_ip,
            "file_path": file_path,
            "catch_server": catch_server,
            "engagement_id": state.engagement_id,
        }
    )
    evidence = _extract_field(result, "evidence", None)
    proofs: list[ExfilEvidence] = []
    if evidence is not None:
        proofs.append(evidence)
    return {"proofs": proofs}


def _extract_fields(obj, field_names: list[str]) -> dict:
    """Extract multiple fields from a Pydantic model or dict.

    Each field defaults to ``[]`` if missing — matches the
    graceful-degradation contract the postex_node loop relies on.
    """
    return {name: _extract_field(obj, name, []) for name in field_names}


def _extract_field(obj, name: str, default):
    """Extract a single field from a Pydantic model or dict.

    Handles both Pydantic v2 models (``hasattr(obj, name)``) and plain
    dicts (``obj.get(name, default)``). Returns ``default`` if neither
    applies (e.g., the underlying tool returned ``None``).
    """
    if obj is None:
        return default
    if hasattr(obj, name):
        return getattr(obj, name)
    if isinstance(obj, dict):
        return obj.get(name, default)
    return default
