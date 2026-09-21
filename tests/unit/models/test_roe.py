from autored.models.roe import RulesOfEngagement


def test_roe_from_yaml(sandbox_roe_yaml):
    roe = RulesOfEngagement.model_validate_yaml(sandbox_roe_yaml)
    assert roe.engagement_name == "Sandbox Engagement"
    assert roe.allowed_ips == ["0.0.0.0/0"]
    assert roe.allowed_techniques == ["*"]
    assert roe.persistence_allowed is True
    assert roe.evasion_allowed is True
    assert roe.exfiltration_allowed is True
    assert roe.data_destruction_allowed is False
    assert roe.kernel_exploits_allowed is True
    assert roe.hitl_mode == "auto_approve"


def test_roe_defaults():
    roe = RulesOfEngagement(
        engagement_name="test",
        operator="op",
        operator_signature="sig",
        allowed_ips=["10.10.10.5"],
        allowed_techniques=["*"],
        persistence_allowed=False,
        evasion_allowed=False,
        exfiltration_allowed=False,
        kernel_exploits_allowed=False,
    )
    assert roe.data_destruction_allowed is False  # always False default
    assert roe.hitl_mode == "always_ask"  # default
