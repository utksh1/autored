from __future__ import annotations

from autored.models.roe import RulesOfEngagement


def test_roe_reexport_is_rules_of_engagement():
    """`autored.models.roe` re-exports `RulesOfEngagement` from `autored.config`."""
    from autored.config import RulesOfEngagement as ConfigRulesOfEngagement

    assert RulesOfEngagement is ConfigRulesOfEngagement


def test_roe_model_fields_keys():
    """Spec §9.2 — `RulesOfEngagement` exposes the full RoE field set."""
    expected = {
        "engagement_name",
        "operator",
        "operator_signature",
        "allowed_ips",
        "allowed_techniques",
        "persistence_allowed",
        "evasion_allowed",
        "exfiltration_allowed",
        "data_destruction_allowed",
        "kernel_exploits_allowed",
        "hitl_mode",
    }
    assert set(RulesOfEngagement.model_fields) == expected
