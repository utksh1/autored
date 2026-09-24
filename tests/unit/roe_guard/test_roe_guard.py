from __future__ import annotations

import pytest

from autored.roe_guard import (
    _ip_in_scope,
    _check_roe_rules,
    _categorize_call,
    RoECheckResult,
    ToolCategory,
)
from autored.config import RulesOfEngagement


def _sandbox_roe(**overrides) -> RulesOfEngagement:
    base = dict(
        engagement_name="t",
        operator="o",
        operator_signature="s",
        allowed_ips=["10.10.10.0/24"],
        allowed_techniques=["*"],
        persistence_allowed=False,
        evasion_allowed=False,
        exfiltration_allowed=False,
        data_destruction_allowed=False,
        kernel_exploits_allowed=False,
        hitl_mode="always_ask",
    )
    base.update(overrides)
    return RulesOfEngagement(**base)


def test_ip_in_scope_single_ip():
    assert _ip_in_scope("10.10.10.5", ["10.10.10.5"]) is True

def test_ip_in_scope_cidr():
    assert _ip_in_scope("10.10.10.5", ["10.10.10.0/24"]) is True
    assert _ip_in_scope("10.10.11.5", ["10.10.10.0/24"]) is False

def test_ip_in_scope_wildcard():
    assert _ip_in_scope("8.8.8.8", ["*"]) is True

def test_ip_in_scope_hostname():
    assert _ip_in_scope("lame.htb", ["lame.htb"]) is True
    assert _ip_in_scope("other.htb", ["lame.htb"]) is False


def test_ip_in_scope_hostname_suffix_safe():
    """Fix I1 — bidirectional endswith allowed `evil.htb` to match `vil.htb`.

    After the fix, suffix match is one-directional with a leading dot, so:
      - "evil.htb" must NOT match "vil.htb" (RoE scope-bypass)
      - "sub.lame.htb" must match "lame.htb" (legitimate subdomain)
      - "lame.htb" must match "lame.htb" (exact equality)
    """
    assert _ip_in_scope("evil.htb", ["vil.htb"]) is False
    assert _ip_in_scope("sub.lame.htb", ["lame.htb"]) is True
    assert _ip_in_scope("lame.htb", ["lame.htb"]) is True

def test_check_roe_rules_allows_recon():
    roe = _sandbox_roe()
    result = _check_roe_rules(roe, "recon", {"target": "10.10.10.5"})
    assert result.allowed is True

def test_check_roe_rules_blocks_out_of_scope():
    roe = _sandbox_roe()
    result = _check_roe_rules(roe, "recon", {"target": "8.8.8.8"})
    assert result.allowed is False
    assert "8.8.8.8" in result.reason

def test_check_roe_rules_blocks_data_destruction_always():
    roe = _sandbox_roe(data_destruction_allowed=True)  # even if RoE says yes
    result = _check_roe_rules(roe, "data_destruction", {})
    assert result.allowed is False

def test_check_roe_rules_blocks_persistence_when_disallowed():
    roe = _sandbox_roe(persistence_allowed=False)
    result = _check_roe_rules(roe, "persistence", {"target": "10.10.10.5"})
    assert result.allowed is False

def test_check_roe_rules_allows_persistence_when_permitted():
    roe = _sandbox_roe(persistence_allowed=True)
    result = _check_roe_rules(roe, "persistence", {"target": "10.10.10.5"})
    assert result.allowed is True

def test_check_roe_rules_blocks_kernel_exploit_without_permission():
    roe = _sandbox_roe(kernel_exploits_allowed=False)
    result = _check_roe_rules(roe, "privesc_kernel", {"target": "10.10.10.5"})
    assert result.allowed is False


class TestPhase5RoERules:
    """Phase 5 lateral/tunnel/cleanup RoE rules (Task 1)."""

    def _roe(self, allowed_techniques=None, allowed_ips=None) -> RulesOfEngagement:
        return RulesOfEngagement(
            engagement_name="t", operator="op", operator_signature="s",
            allowed_ips=allowed_ips or ["0.0.0.0/0"],
            allowed_techniques=allowed_techniques if allowed_techniques is not None else ["*"],
            persistence_allowed=True, evasion_allowed=True,
            exfiltration_allowed=True, kernel_exploits_allowed=True,
        )

    def test_lateral_blocked_when_techniques_pinned_without_lateral(self):
        roe = self._roe(allowed_techniques=["recon", "exploit"])
        result = _check_roe_rules(roe, "lateral", {"target": "10.0.0.2"})
        assert result.allowed is False
        assert "allowed_techniques" in result.reason

    def test_lateral_allowed_with_wildcard(self):
        roe = self._roe(allowed_techniques=["*"])
        result = _check_roe_rules(roe, "lateral", {"target": "10.0.0.2"})
        assert result.allowed is True

    def test_lateral_allowed_when_explicitly_listed(self):
        roe = self._roe(allowed_techniques=["lateral", "exploit"])
        result = _check_roe_rules(roe, "lateral", {"target": "10.0.0.2"})
        assert result.allowed is True

    def test_tunnel_and_cleanup_categories_allowed_by_default(self):
        roe = self._roe()
        assert _check_roe_rules(roe, "tunnel", {"target": "10.0.0.2"}).allowed is True
        # cleanup only ever removes artifacts AutoRed itself created
        assert _check_roe_rules(roe, "cleanup", {}).allowed is True

    def test_categorize_phase5_tools(self):
        assert _categorize_call("impacket_wmiexec") == "lateral"
        assert _categorize_call("impacket_psexec") == "lateral"
        assert _categorize_call("impacket_smbexec") == "lateral"
        assert _categorize_call("crackmapexec") == "lateral"
        assert _categorize_call("ligolo_connect") == "tunnel"
        assert _categorize_call("chisel_reverse") == "tunnel"
        assert _categorize_call("cleanup_execute") == "cleanup"
        assert _categorize_call("cleanup_verify") == "cleanup"

    def test_scope_check_covers_proxy_ip_kwarg(self):
        """Tunnel tools name their endpoint ``proxy_ip`` — the generic
        IP-scope check must honour it (Task 1 roe_guard change)."""
        roe = self._roe(allowed_ips=["192.168.56.0/24"])
        blocked = _check_roe_rules(roe, "tunnel", {"proxy_ip": "10.10.14.5"})
        assert blocked.allowed is False
        ok = _check_roe_rules(roe, "tunnel", {"proxy_ip": "192.168.56.1"})
        assert ok.allowed is True
