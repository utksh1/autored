import os
import yaml
from pathlib import Path
from autored.models.roe import RulesOfEngagement

def load_roe(path: str) -> RulesOfEngagement:
    with open(path) as f:
        data = yaml.safe_load(f)
    return RulesOfEngagement.model_validate(data)

def load_global_config(path: str = "autored.config.yaml") -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    with open(p) as f:
        return yaml.safe_load(f) or {}

def get_env_var(name: str, default: str | None = None) -> str | None:
    return os.environ.get(name, default)
