import pytest
from datetime import datetime
from autored.state import EngagementState
from autored.models.roe import RulesOfEngagement

def test_engagement_state_round_trip(sandbox_roe_yaml):
    roe = RulesOfEngagement.model_validate_yaml(sandbox_roe_yaml)
    state = EngagementState(
        target_scope=["10.10.10.5"],
        operator="test",
        rules_of_engagement=roe,
    )
    serialized = state.model_dump_json()
    restored = EngagementState.model_validate_json(serialized)
    assert restored.target_scope == ["10.10.10.5"]
    assert restored.operator == "test"
    assert restored.phase == "recon"
    assert restored.hosts == []
    assert restored.rules_of_engagement.allowed_ips == ["0.0.0.0/0"]
