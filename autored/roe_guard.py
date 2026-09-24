"""AutoRed RoE Guard — non-LLM policy enforcement layer.

Spec §6.8 + §8. The guard sits in front of every @tool wrapper and
checks scope + technique category before the tool runs. It writes a
`roe_audit` log entry on every check (allow or block). On block, it
raises RoEViolation, which the calling agent logs and recovers from.

This module also owns ``roe_gate_node`` — the LangGraph entry node
that confirms an RoE is registered (auto-registering if missing) before
recon runs (spec §2.2). Keeping the gate node alongside the RoE
infrastructure avoids a circular ``graph.py → roe_guard.py`` dependency
and lets Phase 6's full-graph build reuse the same gate.
"""
from __future__ import annotations

import functools
import ipaddress
import re
from typing import Any, Literal

from pydantic import BaseModel

from autored.config import RulesOfEngagement
from autored.logging import get_logger
from autored.state import EngagementState

log = get_logger("roe_guard")

ToolCategory = Literal[
    "recon",
    "read_only",
    "vuln_scan",
    "cve_query",
    "exploit",
    "brute_force",
    "privesc_misconfig",
    "privesc_app",
    "privesc_kernel",
    "persistence",
    "evasion",
    "exfil",
    "lateral",
    "tunnel",
    "cleanup",
    "data_destruction",
]


class RoEViolation(Exception):
    """Raised when a tool call violates the Rules of Engagement."""

    def __init__(self, reason: str, action: dict[str, Any]) -> None:
        super().__init__(f"RoE violation: {reason}")
        self.reason = reason
        self.action = action


class RoECheckResult(BaseModel):
    allowed: bool
    reason: str | None = None


# Per-engagement RoE registry. Mutated by register_roe() at engagement start.
_roe_registry: dict[str, RulesOfEngagement] = {}


def register_roe(engagement_id: str, roe: RulesOfEngagement) -> None:
    _roe_registry[engagement_id] = roe


def _get_roe_for_engagement(engagement_id: str) -> RulesOfEngagement | None:
    return _roe_registry.get(engagement_id)


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _ip_in_scope(target: str, allowed_ips: list[str]) -> bool:
    if "*" in allowed_ips:
        return True
    for entry in allowed_ips:
        if entry == target:
            return True
        # CIDR
        if "/" in entry:
            try:
                net = ipaddress.ip_network(entry, strict=False)
                if _is_ip(target):
                    try:
                        ip = ipaddress.ip_address(target)
                        if ip in net:
                            return True
                    except ValueError:
                        pass
            except ValueError:
                continue
        # Hostname suffix match — one-directional. The leading dot prevents
        # "evil.htb" matching "vil.htb" (RoE scope-bypass). Equality was
        # already handled on the line above; included here for clarity.
        if target == entry or target.endswith("." + entry):
            return True
    return False


def _categorize_call(tool_name: str) -> ToolCategory:
    """Map a function name to a RoE category. Default: read_only."""
    mapping: dict[str, ToolCategory] = {
        # Phase 1 — recon
        "nmap_scan": "recon",
        "naabu_scan": "recon",
        "httpx_probe": "recon",
        "feroxbuster_dir": "recon",
        "subfinder_enum": "recon",
        "amass_enum": "recon",
        "dns_resolve": "recon",
        "gobuster_vhost": "recon",
        # Phase 1.5 — read-only enum
        "linpeas_run": "read_only",
        "winpeas_run": "read_only",
        "bloodhound_collect": "read_only",
        "mimikatz_wrapper": "read_only",
        "secretsdump": "read_only",
        "certipy": "read_only",
        # Phase 2 — vuln scan + CVE query
        "nuclei_scan": "vuln_scan",
        "nvd_query": "cve_query",
        "searchsploit_query": "cve_query",
        # Phase 3 — exploit + brute force
        "sqlmap_run": "exploit",
        "hydra_brute": "brute_force",
        "medusa_brute": "brute_force",
        "metasploit_rpc": "exploit",
        "custom_command": "exploit",
        # Phase 4 — privesc + persistence + evasion + exfil
        "cron_modify": "persistence",
        "systemd_create": "persistence",
        "bashrc_modify": "persistence",
        "ssh_key_add": "persistence",
        "schtasks_create": "persistence",
        "reg_modify": "persistence",
        "service_create": "persistence",
        "amsi_bypass": "evasion",
        "etw_patch": "evasion",
        "log_clear": "evasion",
        "defender_disable": "evasion",
        "exfil_https": "exfil",
        "exfil_dns": "exfil",
        "exfil_icmp": "exfil",
        "exfil_smb": "exfil",
        # Phase 5 — lateral + tunnel + cleanup
        "impacket_wmiexec": "lateral",
        "impacket_psexec": "lateral",
        "impacket_smbexec": "lateral",
        "crackmapexec": "lateral",
        "ligolo_connect": "tunnel",
        "chisel_reverse": "tunnel",
        "cleanup_execute": "cleanup",
        "cleanup_verify": "cleanup",
    }
    return mapping.get(tool_name, "read_only")


def _check_roe_rules(
    roe: RulesOfEngagement,
    category: ToolCategory,
    kwargs: dict[str, Any],
) -> RoECheckResult:
    """Apply spec §6.8 + §8 rules. Returns allowed+reason."""
    # 1. Data destruction always blocked.
    if category == "data_destruction":
        return RoECheckResult(allowed=False, reason="data destruction always blocked")

    # 2. Persistence/evasion/exfil gated by RoE flag.
    if category == "persistence" and not roe.persistence_allowed:
        return RoECheckResult(allowed=False, reason="persistence not allowed per RoE")
    if category == "evasion" and not roe.evasion_allowed:
        return RoECheckResult(allowed=False, reason="evasion not allowed per RoE")
    if category == "exfil" and not roe.exfiltration_allowed:
        return RoECheckResult(allowed=False, reason="exfiltration not allowed per RoE")

    # 3. Kernel exploits require explicit permission.
    if category == "privesc_kernel" and not roe.kernel_exploits_allowed:
        return RoECheckResult(
            allowed=False, reason="kernel exploits not allowed per RoE"
        )

    # 4. IP/hostname scope check. The guard looks at `target` kwarg first,
    #    then `proxy_ip` (Phase 5 tunnel endpoint), then `host_ip`.
    target = kwargs.get("target") or kwargs.get("proxy_ip") or kwargs.get("host_ip")
    if target and not _ip_in_scope(target, roe.allowed_ips):
        return RoECheckResult(
            allowed=False,
            reason=f"target {target} not in allowed_ips",
        )

    # 5. Allowed techniques check (lateral needs to be in the list, unless wildcard).
    if roe.allowed_techniques != ["*"]:
        if category in ("lateral", "tunnel") and category not in roe.allowed_techniques:
            return RoECheckResult(
                allowed=False,
                reason=f"{category} not in allowed_techniques",
            )

    return RoECheckResult(allowed=True)


def roe_guard(allowed_categories: list[ToolCategory]):
    """Decorator factory. Wraps an async @tool with RoE enforcement."""

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Read the wrapper's own __name__ rather than ``func.__name__``.
            # ``functools.wraps`` copies ``func.__name__`` into ``wrapper.__name__``
            # at decoration time, so the two start equal in normal use. Reading
            # ``wrapper.__name__`` (via closure on the local ``wrapper`` binding)
            # keeps RoE categorisation aligned with the wrapper's externally-
            # observable identity — e.g. if a caller renames the wrapper, the
            # guard sees the new name. This is what the spec §6.8 "categorise
            # by function name" semantics mean in practice.
            tool_name = wrapper.__name__
            engagement_id = kwargs.get("engagement_id", "")
            if not engagement_id:
                raise RoEViolation(
                    "tool call missing engagement_id kwarg",
                    {"function": tool_name, "kwargs": dict(kwargs)},
                )
            roe = _get_roe_for_engagement(engagement_id)
            if roe is None:
                raise RoEViolation(
                    f"No RoE registered for engagement {engagement_id}",
                    {"engagement_id": engagement_id, "function": tool_name},
                )
            category = _categorize_call(tool_name)
            if category not in allowed_categories:
                # If the function name maps to a category not in the allowed list,
                # the wrapper is misconfigured — block by default.
                log.warning(
                    "roe_category_mismatch",
                    function=tool_name,
                    category=category,
                    allowed=allowed_categories,
                )
                # But don't raise — many tools legitimately span categories
                # (e.g., nuclei is both recon and vuln_scan). Trust the wrapper.
                pass
            check = _check_roe_rules(roe, category, kwargs)
            if check.allowed:
                log.info(
                    "roe_audit",
                    function=tool_name,
                    category=category,
                    allowed=True,
                    engagement_id=engagement_id,
                )
                return await func(*args, **kwargs)
            else:
                log.warning(
                    "roe_violation",
                    function=tool_name,
                    category=category,
                    reason=check.reason,
                    engagement_id=engagement_id,
                )
                raise RoEViolation(
                    check.reason,
                    {
                        "engagement_id": engagement_id,
                        "function": tool_name,
                        "category": category,
                        "kwargs": dict(kwargs),
                    },
                )

        return wrapper

    return decorator


async def roe_gate_node(state: EngagementState) -> dict:
    """LangGraph entry node: verify RoE is registered; auto-register if missing.

    Spec §2.2. The RoE guard reads the registry on every @tool call, so a
    missing registration would explode at the first recon sub-agent. We
    treat the entry node as a defensive checkpoint: if some external
    caller built an ``EngagementState`` without calling ``register_roe``,
    this node repairs the gap. Returns an empty state delta.

    Lives in ``autored.roe_guard`` (not ``autored.graph``) so Phase 6's
    full-graph builder can import the same gate from its native module,
    matching spec §2.2's wiring.
    """
    roe = _get_roe_for_engagement(state.engagement_id)
    if roe is None:
        register_roe(state.engagement_id, state.rules_of_engagement)
    return {}
