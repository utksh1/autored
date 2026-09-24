from __future__ import annotations

# RulesOfEngagement lives in autored.config (Task 2) so the RoE loader and
# the model class live together. Re-export here for spec §16 conformance.
from autored.config import RulesOfEngagement

__all__ = ["RulesOfEngagement"]
