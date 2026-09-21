from pydantic import BaseModel, Field
from typing import Literal
import yaml


class RulesOfEngagement(BaseModel):
    engagement_name: str
    operator: str
    operator_signature: str
    allowed_ips: list[str]
    allowed_techniques: list[str]
    persistence_allowed: bool
    evasion_allowed: bool
    exfiltration_allowed: bool
    data_destruction_allowed: bool = False
    kernel_exploits_allowed: bool
    hitl_mode: Literal["always_ask", "auto_approve", "disabled"] = "always_ask"

    @classmethod
    def model_validate_yaml(cls, text: str) -> "RulesOfEngagement":
        """Parse a YAML string into a RulesOfEngagement instance.

        Pydantic v2 does not ship ``model_validate_yaml``; this thin shim
        delegates to ``yaml.safe_load`` + ``model_validate`` so callers can
        use the v1-style API the rest of the codebase expects.
        """
        return cls.model_validate(yaml.safe_load(text))
