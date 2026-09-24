"""AutoRed Pydantic models. One class per file per spec §16."""
from __future__ import annotations

from autored.models.cleanup import (
    CleanupPlan,
    CleanupResult,
    HostCleanupPlan,
)
from autored.models.error import ErrorEvent
from autored.models.foothold import Foothold
from autored.models.host import Host
from autored.models.hypothesis import AttackHypothesis
from autored.models.lateral import (
    MovementPath,
    PivotCandidate,
    PivotRecord,
    SubEngagementRef,
    TunnelConfig,
)
from autored.models.postex import (
    EvasionAction,
    ExfilEvidence,
    PersistenceArtifact,
    PrivescAttempt,
    PrivescCandidate,
    Secret,
    Trust,
    User,
)
from autored.models.report import Lesson, MitreMapping, ReportPaths
from autored.models.roe import RulesOfEngagement
from autored.models.service import Service
from autored.models.vulnerability import Vulnerability
from autored.models.webapp import DiscoveredPath, WebApp

__all__ = [
    "Host",
    "Service",
    "WebApp",
    "DiscoveredPath",
    "Vulnerability",
    "AttackHypothesis",
    "Foothold",
    "ErrorEvent",
    "RulesOfEngagement",
    # Phase 4 — Post-Ex
    "User",
    "Secret",
    "Trust",
    "PrivescCandidate",
    "PrivescAttempt",
    "PersistenceArtifact",
    "EvasionAction",
    "ExfilEvidence",
    # Lateral movement (Phase 5)
    "PivotCandidate",
    "PivotRecord",
    "TunnelConfig",
    "SubEngagementRef",
    "MovementPath",
    # Cleanup (Phase 5)
    "CleanupResult",
    "HostCleanupPlan",
    "CleanupPlan",
    # Report (Phase 6)
    "Lesson",
    "MitreMapping",
    "ReportPaths",
]
