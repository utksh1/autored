"""AutoRed EngagementState — the central inter-agent contract (spec §9.1).

Phase 0 subset: only the fields Phase 1 needs. Phase 2-6 plans append
their own fields (attack_hypotheses, footholds, etc.) with
default_factory=list so prior-phase tests stay green.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from autored.config import RulesOfEngagement
from autored.models import (
    AttackHypothesis,
    CleanupResult,
    DiscoveredPath,
    ErrorEvent,
    EvasionAction,
    ExfilEvidence,
    Foothold,
    Host,
    Lesson,
    MitreMapping,
    MovementPath,
    PersistenceArtifact,
    PivotRecord,
    PrivescAttempt,
    PrivescCandidate,
    ReportPaths,
    Secret,
    Service,
    SubEngagementRef,
    Trust,
    TunnelConfig,
    User,
    Vulnerability,
    WebApp,
)

Phase = Literal[
    "recon", "vuln", "exploit", "postex",
    "lateral", "cleanup", "report", "done",
]


class EngagementState(BaseModel):
    engagement_id: str = Field(default_factory=lambda: str(uuid4()))
    parent_engagement_id: str | None = None
    target_scope: list[str] = Field(default_factory=list)
    operator: str
    started_at: datetime = Field(default_factory=datetime.utcnow)
    phase: Phase = "recon"
    rules_of_engagement: RulesOfEngagement

    # Phase 1 collections
    hosts: list[Host] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)
    web_apps: list[WebApp] = Field(default_factory=list)
    subdomains: list[str] = Field(default_factory=list)
    directories: list[DiscoveredPath] = Field(default_factory=list)

    # Phase 2 collection (forward-declared, default empty so Phase 0 tests stay green)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    attack_hypotheses: list[AttackHypothesis] = Field(default_factory=list)

    # Phase 3 collection (forward-declared, default empty so Phase 0-2 tests stay green)
    footholds: list[Foothold] = Field(default_factory=list)

    # Phase 4 — Post-Ex (forward-declared, default empty so Phase 0-3 tests stay green)
    local_users: list[User] = Field(default_factory=list)
    harvested_secrets: list[Secret] = Field(default_factory=list)
    trust_relationships: list[Trust] = Field(default_factory=list)
    privesc_candidates: list[PrivescCandidate] = Field(default_factory=list)
    privesc_attempts: list[PrivescAttempt] = Field(default_factory=list)
    persistence_artifacts: list[PersistenceArtifact] = Field(default_factory=list)
    evasion_actions: list[EvasionAction] = Field(default_factory=list)
    exfiltration_proof: list[ExfilEvidence] = Field(default_factory=list)

    # Lateral movement (Phase 5+)
    pivots: list[PivotRecord] = Field(default_factory=list)
    tunnels: list[TunnelConfig] = Field(default_factory=list)
    sub_engagements: list[SubEngagementRef] = Field(default_factory=list)
    movement_paths: list[MovementPath] = Field(default_factory=list)

    # Cleanup (Phase 5+)
    cleanup_results: list[CleanupResult] = Field(default_factory=list)

    # Cross-phase
    evidence_paths: list[str] = Field(default_factory=list)
    iteration_count: int = 0
    errors: list[ErrorEvent] = Field(default_factory=list)
    summary: str = ""

    # Report (Phase 6+)
    lessons: list[Lesson] = Field(default_factory=list)
    mitre_mappings: list[MitreMapping] = Field(default_factory=list)
    report_paths: ReportPaths | None = None

    # Non-serialized runtime attribute (Phase 3 EventBus, etc.).
    # `validate_assignment` enforces Phase Literal type-safety on
    # `state.phase = "bogus"` re-assignment (spec §9.1). `extra="allow"`
    # lets Phase 3 attach runtime attrs (`state.event_bus = EventBus()`)
    # without declaring them as fields; `arbitrary_types_allowed` permits
    # arbitrary classes (e.g., EventBus) for any Phase 3 runtime attrs that
    # are later promoted to real fields.
    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        validate_assignment=True,
        extra="allow",
    )
