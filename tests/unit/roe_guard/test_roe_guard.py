# tests/unit/roe_guard/test_roe_guard.py
from autored.roe_guard import _ip_in_scope, _check_roe_rules
from autored.models.roe import RulesOfEngagement


def test_ip_in_scope_single_ip():
    assert _ip_in_scope("10.10.10.5", ["10.10.10.5"]) is True
    assert _ip_in_scope("10.10.10.6", ["10.10.10.5"]) is False


def test_ip_in_scope_cidr():
    assert _ip_in_scope("10.10.10.50", ["10.10.10.0/24"]) is True
    assert _ip_in_scope("10.10.11.50", ["10.10.10.0/24"]) is False


def test_ip_in_scope_wildcard():
    assert _ip_in_scope("8.8.8.8", ["0.0.0.0/0"]) is True
    assert _ip_in_scope("8.8.8.8", ["*"]) is True


def test_ip_in_scope_hostname():
    assert _ip_in_scope("lame.htb", ["lame.htb"]) is True
    assert _ip_in_scope("lame.htb", ["htb"]) is False  # exact match required


def test_check_roe_rules_allows_recon():
    roe = RulesOfEngagement(
        engagement_name="t", operator="o", operator_signature="s",
        allowed_ips=["10.10.10.5"], allowed_techniques=["*"],
        persistence_allowed=False, evasion_allowed=False,
        exfiltration_allowed=False, kernel_exploits_allowed=False,
    )
    result = _check_roe_rules(roe, "recon", {"target": "10.10.10.5"})
    assert result.allowed is True


def test_check_roe_rules_blocks_out_of_scope():
    roe = RulesOfEngagement(
        engagement_name="t", operator="o", operator_signature="s",
        allowed_ips=["10.10.10.0/24"], allowed_techniques=["*"],
        persistence_allowed=False, evasion_allowed=False,
        exfiltration_allowed=False, kernel_exploits_allowed=False,
    )
    result = _check_roe_rules(roe, "recon", {"target": "8.8.8.8"})
    assert result.allowed is False
    assert "not in allowed_ips" in result.reason


def test_check_roe_rules_blocks_data_destruction_always():
    roe = RulesOfEngagement(
        engagement_name="t", operator="o", operator_signature="s",
        allowed_ips=["*"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, data_destruction_allowed=True,  # even if True
        kernel_exploits_allowed=True,
    )
    result = _check_roe_rules(roe, "data_destruction", {"target": "10.10.10.5"})
    assert result.allowed is False
    assert "always blocked" in result.reason


def test_check_roe_rules_blocks_persistence_when_disallowed():
    roe = RulesOfEngagement(
        engagement_name="t", operator="o", operator_signature="s",
        allowed_ips=["*"], allowed_techniques=["*"],
        persistence_allowed=False, evasion_allowed=True,
        exfiltration_allowed=True, kernel_exploits_allowed=True,
    )
    result = _check_roe_rules(roe, "persistence", {"target": "10.10.10.5"})
    assert result.allowed is False
    assert "persistence" in result.reason
