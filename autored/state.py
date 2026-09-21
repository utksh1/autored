from pydantic import BaseModel, Field
from datetime import datetime
from typing import Literal, Optional
from uuid import uuid4
from autored.models import (
    RulesOfEngagement,
    Host,
    Service,
    WebApp,
    DiscoveredPath,
    Vulnerability,
    AttackHypothesis,
    Foothold,
    ErrorEvent,
)


class EngagementState(BaseModel):
    engagement_id: str = Field(default_factory=lambda: str(uuid4()))
    parent_engagement_id: Optional[str] = None
    target_scope: list[str]
    operator: str
    started_at: datetime = Field(default_factory=datetime.utcnow)
    phase: Literal[
        "recon", "vuln", "exploit", "postex", "lateral", "cleanup", "report", "done"
    ] = "recon"

    rules_of_engagement: RulesOfEngagement

    hosts: list[Host] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)
    web_apps: list[WebApp] = Field(default_factory=list)
    subdomains: list[str] = Field(default_factory=list)
    directories: list[DiscoveredPath] = Field(default_factory=list)

    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    attack_hypotheses: list[AttackHypothesis] = Field(default_factory=list)
    footholds: list[Foothold] = Field(default_factory=list)

    evidence_paths: list[str] = Field(default_factory=list)
    iteration_count: int = 0
    errors: list[ErrorEvent] = Field(default_factory=list)
    summary: str = ""
