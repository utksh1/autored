import pytest
from pathlib import Path

@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"

@pytest.fixture
def sandbox_roe_yaml() -> str:
    return """engagement_name: "Sandbox Engagement"
operator: "test"
operator_signature: "sandbox-mode"
allowed_ips:
  - "0.0.0.0/0"
allowed_techniques:
  - "*"
persistence_allowed: true
evasion_allowed: true
exfiltration_allowed: true
data_destruction_allowed: false
kernel_exploits_allowed: true
hitl_mode: "auto_approve"
"""
