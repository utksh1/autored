"""AutoRed config loader — RoE YAML + global config + env var access."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError
from typing import Literal


class RulesOfEngagement(BaseModel):
    """Spec §9.2 — Rules of Engagement model."""
    engagement_name: str
    operator: str
    operator_signature: str
    allowed_ips: list[str] = Field(default_factory=list)
    allowed_techniques: list[str] = Field(default_factory=list)
    persistence_allowed: bool = False
    evasion_allowed: bool = False
    exfiltration_allowed: bool = False
    data_destruction_allowed: bool = False
    kernel_exploits_allowed: bool = False
    hitl_mode: Literal["always_ask", "auto_approve", "disabled"] = "always_ask"


_REQUIRED_ROE_FIELDS = (
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
)


def load_roe(path: str) -> RulesOfEngagement:
    """Load a RoE YAML file into a RulesOfEngagement model."""
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return RulesOfEngagement.model_validate(data)


def load_global_config(path: str) -> dict[str, Any]:
    """Load the global autored.config.yaml into a plain dict."""
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def get_env_var(name: str, default: str | None = None) -> str | None:
    """Return the env var value, or default if unset."""
    return os.environ.get(name, default)


def validate_roe_yaml(text: str) -> list[str]:
    """Validate a RoE YAML string. Returns a list of error messages (empty if valid)."""
    errors: list[str] = []
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return [f"YAML parse error: {exc}"]
    if not isinstance(data, dict):
        return ["Top-level YAML must be a mapping"]
    for field in _REQUIRED_ROE_FIELDS:
        if field not in data:
            errors.append(f"Missing required field: {field}")
    if errors:
        return errors
    try:
        RulesOfEngagement.model_validate(data)
    except ValidationError as exc:
        for err in exc.errors():
            loc = ".".join(str(p) for p in err["loc"])
            errors.append(f"{loc}: {err['msg']}")
    return errors
