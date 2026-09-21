import ipaddress
from functools import wraps
from typing import Literal

from pydantic import BaseModel

from autored.logging import get_logger
from autored.models.roe import RulesOfEngagement

log = get_logger("roe_guard")

ToolCategory = Literal[
    "recon", "read_only", "vuln_scan", "cve_query",
    "exploit", "brute_force",
    "privesc_misconfig", "privesc_app", "privesc_kernel",
    "persistence", "evasion", "exfil",
    "lateral", "tunnel", "cleanup",
    "data_destruction",
]


class RoEViolation(Exception):
    def __init__(self, reason: str, action: dict):
        self.reason = reason
        self.action = action
        super().__init__(f"RoE violation: {reason}")


class RoECheckResult(BaseModel):
    allowed: bool
    reason: str | None = None


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        try:
            ipaddress.ip_network(s, strict=False)
            return True
        except ValueError:
            return False


def _ip_in_scope(target: str, allowed_ips: list[str]) -> bool:
    if "*" in allowed_ips:
        return True
    try:
        target_ip = ipaddress.ip_address(target)
        for allowed in allowed_ips:
            try:
                if "/" in allowed:
                    network = ipaddress.ip_network(allowed, strict=False)
                    if target_ip in network:
                        return True
                else:
                    if target_ip == ipaddress.ip_address(allowed):
                        return True
            except ValueError:
                continue
        return False
    except ValueError:
        # target is a hostname
        return any(target == allowed for allowed in allowed_ips if not _is_ip(allowed))


def _check_roe_rules(roe: RulesOfEngagement, category: ToolCategory, kwargs: dict) -> RoECheckResult:
    # Hard limits
    if category == "data_destruction":
        return RoECheckResult(allowed=False, reason="data destruction always blocked")

    # Category-specific
    if category == "persistence" and not roe.persistence_allowed:
        return RoECheckResult(allowed=False, reason="persistence not allowed per RoE")
    if category == "evasion" and not roe.evasion_allowed:
        return RoECheckResult(allowed=False, reason="evasion not allowed per RoE")
    if category == "exfil" and not roe.exfiltration_allowed:
        return RoECheckResult(allowed=False, reason="exfiltration not allowed per RoE")
    if category == "privesc_kernel" and not roe.kernel_exploits_allowed:
        return RoECheckResult(allowed=False, reason="kernel exploits not allowed per RoE")

    # IP scope check
    target = kwargs.get("target")
    if target and not _ip_in_scope(target, roe.allowed_ips):
        return RoECheckResult(allowed=False, reason=f"target {target} not in allowed_ips")

    return RoECheckResult(allowed=True)


# Global registry of RoE per engagement (populated by CLI at engagement start)
_roe_registry: dict[str, RulesOfEngagement] = {}


def register_roe(engagement_id: str, roe: RulesOfEngagement) -> None:
    _roe_registry[engagement_id] = roe


def _get_roe_for_engagement(engagement_id: str) -> RulesOfEngagement | None:
    return _roe_registry.get(engagement_id)


def roe_guard(allowed_categories: list[ToolCategory]):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            engagement_id = kwargs.get("engagement_id", "")
            roe = _get_roe_for_engagement(engagement_id)
            if roe is None:
                raise RoEViolation(
                    f"No RoE registered for engagement {engagement_id}",
                    {"tool": func.__name__, "engagement_id": engagement_id},
                )

            category = _categorize_call(func.__name__)
            if category not in allowed_categories:
                raise RoEViolation(
                    f"Tool {func.__name__} not allowed for category {category}",
                    {"tool": func.__name__, "category": category},
                )

            check_result = _check_roe_rules(roe, category, kwargs)
            if not check_result.allowed:
                log.warning("roe_violation",
                            tool=func.__name__, reason=check_result.reason, kwargs=kwargs)
                raise RoEViolation(check_result.reason, {"tool": func.__name__, **kwargs})

            log.info("roe_audit",
                     tool=func.__name__, category=category,
                     target=kwargs.get("target", ""), allowed=True)
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def _categorize_call(tool_name: str) -> ToolCategory:
    # Map tool name to category — used by the guard
    TOOL_CATEGORIES = {
        # Phase 1
        "nmap_scan": "recon",
        "naabu_scan": "recon",
        "httpx_probe": "recon",
        "feroxbuster_dir": "recon",
        "nuclei_scan": "vuln_scan",
        "subfinder_enum": "recon",
        "amass_enum": "recon",
        "dns_resolve": "recon",
        "gobuster_vhost": "recon",
        # Phase 2
        "nvd_query": "cve_query",
        "searchsploit_query": "cve_query",
        # Phase 3+
        "sqlmap_run": "exploit",
        "hydra_brute": "brute_force",
        # Phase 4+
        "linpeas_run": "read_only",
        "winpeas_run": "read_only",
    }
    return TOOL_CATEGORIES.get(tool_name, "read_only")
