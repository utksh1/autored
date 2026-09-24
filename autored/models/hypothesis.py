"""AttackHypothesis model — Phase 2 (spec §16).

A ranked attack hypothesis produced by the Vuln Agent. Each hypothesis
proposes a specific technique to exploit a target, with confidence,
rationale, and the tool that would execute it. Phase 3's exploit
agents consume these to drive tool selection.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class AttackHypothesis(BaseModel):
    """A ranked attack hypothesis produced by the Vuln Agent.

    Each hypothesis proposes a specific technique to exploit a target,
    with confidence, rationale, and the tool that would execute it.
    """

    rank: int = Field(ge=1)
    target: str
    technique: str
    cve: str | None = None
    expected_outcome: str
    tool: Literal["sqlmap", "hydra", "metasploit", "impacket", "custom"]
    tool_module: str | None = None  # e.g., "exploit/windows/smb/ms17_010_eternalblue"
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
    prerequisites: list[str] = Field(default_factory=list)
    risks: list[str] = Field(default_factory=list)
    command_preview: str | None = None  # proposed command, not yet executed
