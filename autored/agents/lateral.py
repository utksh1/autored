"""Lateral Agent — LangGraph node that pivots onto new hosts and
spawns recursive sub-engagements (spec §6.5, Phase 5).

Per pivot candidate, in order:

  1. **RoE scope pre-check** — candidates whose target is outside
     ``allowed_ips`` are dropped BEFORE the HitL gate (an operator is
     never asked to approve something the scope forbids — same rule as
     Phase 4's kernel-exploit check). Review Focus #1.
  2. **HitL gate** (EventBus pattern; auto-approved in sandbox mode).
  3. **Pivot execution** via the PivotExecutor sub-agent. A failed
     pivot does NOT abort the loop — the next candidate is tried.
     Review Focus #2.
  4. **Optional tunnel** via TunnelSetup (only when the pivot record
     says one is needed; failures are non-fatal).
  5. **Sub-engagement spawn** — a full Phase 4 run against the pivot
     target with its own ID / folder / checkpoints and a RoE narrowed
     to that single host. ``SubEngagementDepthError`` is caught and
     skipped (the pivot itself still counts). Review Focus #3.

Candidate identification: (credential, target_host, method) triples
from harvested secrets crossed with pivot targets — un-footholded
known hosts plus any new host IPs surfaced in ``Trust.details``.
Sorted by confidence, capped at ``MAX_PIVOTS``.

I1 (Phase 3 fix wave): the EventBus travels via
``config["configurable"]["event_bus"]`` (RunnableConfig), NOT via
``state.event_bus``. LangGraph's reducer round-trips state through
``model_dump() + model_validate()`` which strips the
``__pydantic_extra__`` dict where ``state.event_bus = ...`` was stored
under ``extra="allow"``. The RunnableConfig is the standard LangGraph
channel for runtime objects (it never crosses the reducer boundary).

Deviations from the spec §6.5 sketch are documented in the plan
(``Secret.host_ip`` vs ``source_host``, username parsed from
``Secret.source``, ``Trust.details["hosts"]`` vs ``trust.host``,
scope-check-before-HitL, headless fail-open gate).
"""
from __future__ import annotations

from langchain_core.runnables import RunnableConfig

from autored.logging import get_logger
from autored.models.lateral import (
    MovementPath,
    PivotCandidate,
    SubEngagementRef,
)
from autored.roe_guard import _ip_in_scope, register_roe
from autored.state import EngagementState

# Sub-agent @tool entrypoints imported as module-level names so test
# patches like ``patch("autored.agents.lateral.pivotexecutor_subagent")``
# are visible to the helper bodies at call time (the helper references
# the module global, which ``patch`` replaces in-place). Same pattern as
# ``autored/agents/postex.py``.
from autored.subagents.pivotexecutor import pivotexecutor_subagent
from autored.subagents.tunnelsetup import tunnelsetup_subagent

# Sub-engagement spawner + its depth-cap exception. ``spawn_sub_engagement``
# is a module-level name so tests can patch
# ``autored.agents.lateral.spawn_sub_engagement``; ``SubEngagementDepthError``
# is the real exception class so the ``except`` clause catches it even
# when the function is patched.
from autored.agents.sub_engagement import (  # noqa: E402
    SubEngagementDepthError,
    spawn_sub_engagement,
)

log = get_logger("agents.lateral")

# Bound on pivots per lateral pass — each pivot spawns a full
# sub-engagement (recon → vuln → exploit → postex), so this bounds
# engagement wall-clock time.
MAX_PIVOTS = 3

# Secret.source prefixes whose trailing path segment is a username
# (Phase 4's CredHarvester convention).
_CRED_SOURCE_PREFIXES = ("mimikatz:", "secretsdump:", "credharvester:")


async def lateral_node(
    state: EngagementState, config: RunnableConfig
) -> dict:
    """LangGraph node: run the Lateral Agent.

    Returns a state-dict patch with new pivots / tunnels /
    sub_engagements / movement_paths and ``phase="cleanup"``.

    The EventBus is pulled from ``config["configurable"]["event_bus"]``
    per the Phase 3 I1 fix — the bus is a non-state runtime object and
    the RunnableConfig is the standard LangGraph channel for those.
    """
    log.info("lateral_start", engagement_id=state.engagement_id)

    # Defensive RoE registration (same as postex_node — tests / resume
    # / direct-node-entry paths bypass the CLI).
    register_roe(state.engagement_id, state.rules_of_engagement)

    bus = _get_bus(config)
    foothold_ips = {f.host_ip for f in state.footholds}

    candidates = _identify_pivot_candidates(
        state.harvested_secrets,
        state.trust_relationships,
        state.hosts,
        foothold_ips,
    )
    candidates.sort(key=lambda c: c.confidence, reverse=True)

    # RoE scope pre-check — BEFORE any HitL gate (Review Focus #1).
    in_scope = [
        c
        for c in candidates
        if _ip_in_scope(c.target_host, state.rules_of_engagement.allowed_ips)
    ]
    dropped = len(candidates) - len(in_scope)
    if dropped:
        log.info("lateral_candidates_out_of_scope", dropped=dropped)
    in_scope = in_scope[:MAX_PIVOTS]

    pivots = []
    tunnels = []
    sub_engagements = []
    movement_paths = []

    for candidate in in_scope:
        if state.rules_of_engagement.hitl_mode != "auto_approve":
            approved = await _hitl_lateral_gate(candidate, state, bus)
            if not approved:
                log.info(
                    "lateral_candidate_rejected",
                    target=candidate.target_host,
                )
                continue

        output = await pivotexecutor_subagent.ainvoke(
            {
                "candidate": candidate.model_dump(),
                "engagement_id": state.engagement_id,
            }
        )
        if not output.success or output.pivot is None:
            # Failed pivot → try the next candidate (Review Focus #2).
            log.info("lateral_pivot_failed", target=candidate.target_host)
            continue

        pivot = output.pivot
        pivots.append(pivot)
        movement_paths.append(
            MovementPath(
                from_host=candidate.source_host,
                to_host=candidate.target_host,
                method=pivot.method,
                credential_used=candidate.credential_id,
            )
        )

        if pivot.needs_tunnel:
            tunnel_out = await tunnelsetup_subagent.ainvoke(
                {
                    "pivot": pivot.model_dump(),
                    "engagement_id": state.engagement_id,
                }
            )
            tunnel = getattr(tunnel_out, "tunnel", None)
            if tunnel is not None:
                tunnels.append(tunnel)

        sub_id = f"{state.engagement_id}_sub_{len(sub_engagements) + 1:02d}"
        try:
            sub_state = await spawn_sub_engagement(
                parent_state=state,
                sub_id=sub_id,
                target_host=pivot.target_host,
                pivot_method=pivot.method,
                credentials=pivot.credentials_used,
            )
            status = "completed" if sub_state.phase == "done" else "failed"
            summary = sub_state.summary or (
                f"sub-engagement reached phase {sub_state.phase}"
            )
        except SubEngagementDepthError as exc:
            # Review Focus #3 — log, skip, keep the pivot.
            log.warning("lateral_depth_cap", sub_id=sub_id, error=str(exc))
            continue
        except Exception as exc:  # noqa: BLE001 — sub failure isn't fatal
            log.warning("sub_engagement_failed", sub_id=sub_id, error=str(exc))
            status, summary = "failed", f"sub-engagement error: {exc}"

        sub_engagements.append(
            SubEngagementRef(
                sub_id=sub_id,
                target_host=pivot.target_host,
                pivot_method=pivot.method,
                status=status,
                summary=summary,
                sub_state_path=f"engagements/{sub_id}/state.json",
            )
        )

    log.info(
        "lateral_done",
        pivots=len(pivots),
        tunnels=len(tunnels),
        sub_engagements=len(sub_engagements),
    )
    return {
        "pivots": state.pivots + pivots,
        "tunnels": state.tunnels + tunnels,
        "sub_engagements": state.sub_engagements + sub_engagements,
        "movement_paths": state.movement_paths + movement_paths,
        "phase": "cleanup",
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


def _extract_username_from_source(source: str) -> str:
    """Parse the username out of a Secret.source cred string.

    Phase 4's CredHarvester encodes ``"secretsdump:SAM/<username>"`` /
    ``"mimikatz:<provider>/<username>"`` / ``"credharvester:.../<u>"``.
    Non-credential sources (file paths, registry keys) yield ``""``.
    """
    if source.startswith(_CRED_SOURCE_PREFIXES) and "/" in source:
        return source.rsplit("/", 1)[-1].strip()
    return ""


def _select_pivot_method(secret) -> str | None:
    """Pick the pivot method for a harvested secret.

    Windows-oriented (GoAD): NTLM hashes → wmiexec (pass-the-hash),
    passwords → crackmapexec (validated spray). ``ssh`` pivots need the
    Phase 6 foothold session manager — not selectable yet. Returns
    ``None`` when the secret type has no backing tool (the secret is
    skipped).
    """
    if secret.secret_type == "hash":
        return "wmiexec"
    if secret.secret_type == "password":
        return "crackmapexec"
    return None


def _calculate_confidence(secret, method: str) -> float:
    """Heuristic confidence for a pivot candidate (0.0-0.95).

    Base 0.7 for hashes (pass-the-hash is high-fidelity on Windows),
    0.5 for passwords (spray attempts are noisier). ``+0.1`` for
    ``wmiexec`` (PtH is more reliable than spray). ``+0.1`` when the
    source is a memory / SAM-derived cred (mimikatz / secretsdump
    yield higher-quality material than a manual credharvester paste).
    Capped at 0.95 so the operator always sees room for doubt.
    """
    base = 0.7 if secret.secret_type == "hash" else 0.5
    if method == "wmiexec":
        base += 0.1  # PtH is high-fidelity on Windows
    if secret.source.startswith(("mimikatz:", "secretsdump:")):
        base += 0.1  # memory / SAM derived — high quality creds
    return min(base, 0.95)


def _identify_pivot_candidates(
    secrets, trusts, known_hosts, foothold_ips
) -> list[PivotCandidate]:
    """Find (credential, target_host, method) triples for lateral movement.

    Target hosts: IPs surfaced in ``Trust.details["hosts"]`` that are
    not yet known, plus known hosts without a foothold. Credentials:
    harvested secrets whose source encodes a username (so we know who
    to authenticate as) AND whose secret type maps to a backing pivot
    tool (``_select_pivot_method`` returns non-None).

    Each (credential, target) pair produces one candidate. The caller
    sorts by confidence and applies the ``MAX_PIVOTS`` cap.
    """
    known_ips = {h.ip for h in known_hosts}
    target_hosts: list[str] = []

    for trust in trusts:
        details = trust.details if isinstance(trust.details, dict) else {}
        for host_ip in details.get("hosts", []):
            if (
                _is_ipv4(host_ip)
                and host_ip not in known_ips
                and host_ip not in target_hosts
            ):
                target_hosts.append(host_ip)

    for host in known_hosts:
        if host.ip not in foothold_ips and host.ip not in target_hosts:
            target_hosts.append(host.ip)

    if not target_hosts:
        return []

    candidates: list[PivotCandidate] = []
    for secret in secrets:
        username = _extract_username_from_source(secret.source)
        if not username:
            continue
        method = _select_pivot_method(secret)
        if method is None:
            continue
        for target in target_hosts:
            candidates.append(
                PivotCandidate(
                    credential_id=secret.id,
                    username=username,
                    cred_type=secret.secret_type,
                    secret_value=secret.secret_value,
                    source_host=secret.host_ip,
                    target_host=target,
                    method=method,
                    confidence=_calculate_confidence(secret, method),
                )
            )
    return candidates


def _is_ipv4(text: str) -> bool:
    """Cheap dotted-quad check (Trust details may carry hostnames)."""
    parts = text.split(".")
    return (
        len(parts) == 4
        and all(p.isdigit() for p in parts)
        and all(0 <= int(p) <= 255 for p in parts)
    )


async def _hitl_lateral_gate(
    candidate: PivotCandidate,
    state: EngagementState,
    bus,
) -> bool:
    """HitL gate for one pivot candidate (EventBus pattern).

    Sandbox mode (``hitl_mode == "auto_approve"``) short-circuits before
    any blocking wait. A missing EventBus in non-sandbox mode fails OPEN
    with a warning — a headless ``--no-tui`` run has nobody to ask
    (matches the Exploit Agent's headless shape).

    The bus's response envelope is ``{"approved": bool, ...}`` — a
    more compact shape than the privesc / persistence gates' ``{"response":
    "approve" | "reject", ...}`` because the lateral gate has no edit /
    skip affordance (the operator either greenlights the pivot or
    doesn't; there's no command to modify).
    """
    if bus is not None:
        await bus.emit_to_tui(
            {
                "type": "hitl_gate",
                "gate": "lateral_pivot",
                "target": candidate.target_host,
                "method": candidate.method,
                "username": candidate.username,
                "confidence": candidate.confidence,
            }
        )
    if state.rules_of_engagement.hitl_mode == "auto_approve":
        log.info("lateral_auto_approved", target=candidate.target_host)
        return True
    if bus is None:
        log.warning(
            "lateral_gate_headless_fail_open",
            target=candidate.target_host,
        )
        return True
    response = await bus.wait_for_tui_response()
    approved = bool(response.get("approved", False))
    log.info(
        "lateral_gate_response",
        target=candidate.target_host,
        approved=approved,
    )
    return approved
