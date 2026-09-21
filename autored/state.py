from pydantic import BaseModel, Field
from datetime import datetime
from typing import Any, Literal, Optional
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
    User,
    Secret,
    Trust,
    PrivescCandidate,
    PrivescAttempt,
    PersistenceArtifact,
    EvasionAction,
    ExfilEvidence,
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

    # Post-Ex (Phase 4+)
    local_users: list[User] = Field(default_factory=list)
    harvested_secrets: list[Secret] = Field(default_factory=list)
    trust_relationships: list[Trust] = Field(default_factory=list)
    privesc_candidates: list[PrivescCandidate] = Field(default_factory=list)
    privesc_attempts: list[PrivescAttempt] = Field(default_factory=list)
    persistence_artifacts: list[PersistenceArtifact] = Field(default_factory=list)
    evasion_actions: list[EvasionAction] = Field(default_factory=list)
    exfiltration_proof: list[ExfilEvidence] = Field(default_factory=list)

    evidence_paths: list[str] = Field(default_factory=list)
    iteration_count: int = 0
    errors: list[ErrorEvent] = Field(default_factory=list)
    summary: str = ""

    # EventBus is injected by the graph runner at runtime (Phase 3+) so
    # LangGraph nodes can emit HitL gate events and block on operator
    # responses. Declared as ``Any`` with ``exclude=True`` because it
    # contains non-serialisable ``asyncio.Queue`` instances — Pydantic
    # will skip it during ``model_dump`` / ``model_dump_json`` (which
    # keeps the LangGraph SQLite checkpointer happy) and existing code
    # that does not set it sees the default ``None``.
    event_bus: Any = Field(default=None, exclude=True)
