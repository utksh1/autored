from __future__ import annotations

from pathlib import Path

import pytest

from autored.config import load_roe, load_global_config, get_env_var, validate_roe_yaml


def test_load_roe_from_sandbox_yaml(sandbox_roe_yaml: str):
    roe = load_roe(sandbox_roe_yaml)
    assert roe.engagement_name == "Sandbox Engagement"
    assert roe.operator == "operator"
    assert roe.allowed_ips == ["0.0.0.0/0"]
    assert roe.persistence_allowed is True
    assert roe.evasion_allowed is True
    assert roe.exfiltration_allowed is True
    assert roe.data_destruction_allowed is False
    assert roe.kernel_exploits_allowed is True
    assert roe.hitl_mode == "auto_approve"


def test_load_global_config(tmp_path: Path):
    cfg = tmp_path / "autored.config.yaml"
    cfg.write_text(
        "log_dir: logs\nengagements_dir: engagements\n"
        'db_path: db/engagements.sqlite\nchroma_path: db/chroma\n'
        'default_sandbox_roe: roe-sandbox.yaml\n'
        "llm:\n  default_temperature: 0.2\n  default_max_tokens: 8192\n"
        "  default_timeout: 120\n"
        "tools:\n  nmap_timeout: 600\n  nuclei_timeout: 900\n"
        "subagents:\n  max_execution_time: 300\n  max_retries: 3\n"
    )
    config = load_global_config(str(cfg))
    assert config["log_dir"] == "logs"
    assert config["db_path"] == "db/engagements.sqlite"
    assert config["llm"]["default_temperature"] == 0.2


def test_get_env_var_with_default(monkeypatch):
    monkeypatch.delenv("AUTORED_FAKE_VAR", raising=False)
    assert get_env_var("AUTORED_FAKE_VAR", "fallback") == "fallback"


def test_get_env_var_without_default(monkeypatch):
    monkeypatch.delenv("AUTORED_FAKE_VAR", raising=False)
    assert get_env_var("AUTORED_FAKE_VAR") is None


def test_validate_roe_yaml_accepts_valid_config():
    valid = (
        "engagement_name: Test\noperator: op\noperator_signature: sig\n"
        'allowed_ips: ["10.10.10.0/24"]\nallowed_techniques: ["*"]\n'
        "persistence_allowed: false\nevasion_allowed: false\n"
        "exfiltration_allowed: false\ndata_destruction_allowed: false\n"
        "kernel_exploits_allowed: false\nhitl_mode: always_ask\n"
    )
    assert validate_roe_yaml(valid) == []


def test_validate_roe_yaml_rejects_missing_fields():
    invalid = "engagement_name: Test\noperator: op\n"
    errors = validate_roe_yaml(invalid)
    assert len(errors) > 0
    assert any("operator_signature" in e for e in errors)


def test_validate_roe_yaml_rejects_invalid_hitl_mode():
    invalid = (
        "engagement_name: T\noperator: o\noperator_signature: s\n"
        'allowed_ips: ["0.0.0.0/0"]\nallowed_techniques: ["*"]\n'
        "persistence_allowed: true\nevasion_allowed: true\n"
        "exfiltration_allowed: true\ndata_destruction_allowed: false\n"
        "kernel_exploits_allowed: true\nhitl_mode: maybe\n"
    )
    errors = validate_roe_yaml(invalid)
    assert any("hitl_mode" in e for e in errors)


# --- Phase 6 (Task 17): validate_roe_yaml additional cases --------------- #

VALID_ROE_YAML = """
engagement_name: "HTB Lame Test"
operator: operator
operator_signature: signed
allowed_ips: ["10.10.10.5"]
allowed_techniques: ["*"]
persistence_allowed: false
evasion_allowed: false
exfiltration_allowed: false
data_destruction_allowed: false
kernel_exploits_allowed: false
hitl_mode: always_ask
"""


def test_validate_roe_yaml_accepts_full_valid_config():
    assert validate_roe_yaml(VALID_ROE_YAML) == []


def test_validate_roe_yaml_rejects_bad_yaml():
    errors = validate_roe_yaml("this: [is: not: valid: yaml")
    assert errors and "yaml" in errors[0].lower()


def test_validate_roe_yaml_rejects_schema_violations():
    broken = VALID_ROE_YAML.replace("hitl_mode: always_ask", "hitl_mode: maybe")
    errors = validate_roe_yaml(broken)
    assert errors  # invalid literal rejected


def test_validate_roe_yaml_rejects_missing_fields_only_name():
    errors = validate_roe_yaml("engagement_name: x\n")
    assert errors
