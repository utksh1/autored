"""Post-Ex models — Phase 4 (spec §16).

Each model captures a single post-exploitation artefact so the
EngagementState can round-trip the kill chain's later phases:

  * ``User`` / ``Secret`` / ``Trust`` — enumeration output from
    linpeas/winpeas/mimikatz/secretsdump/certipy.
  * ``PrivescCandidate`` / ``PrivescAttempt`` — the privesc loop
    (find candidate → attempt → record outcome).
  * ``PersistenceArtifact`` — every persistence implant with a
    mandatory ``removal_command`` (spec §6.4, §9.2 — review focus:
    persistence MUST be reversible).
  * ``EvasionAction`` — every evasion technique applied.
  * ``ExfilEvidence`` — provenance record for exfil events,
    including the catch-server log path (spec §6.8).

All eight live in a single module per the Phase 4 T1 brief — the
grain is "phase" rather than "model" for the post-ex cluster.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field


class User(BaseModel):
    """Local account enumerated on a foothold host."""

    host_ip: str
    username: str
    uid: str | None = None  # Linux UID or Windows SID
    groups: list[str] = Field(default_factory=list)
    is_admin: bool = False
    is_service_account: bool = False


class Secret(BaseModel):
    """A harvested credential or sensitive config blob."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    host_ip: str
    secret_type: Literal["password", "hash", "key", "token", "config", "other"]
    secret_value: str
    source: str  # file path, registry key, etc.
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class Trust(BaseModel):
    """A trust relationship discovered on a host (AD domain, NFS export, etc.)."""

    host_ip: str
    trust_type: Literal["ad_domain", "ssh_trust", "nfs_export", "smb_share", "kerberos"]
    target: str  # domain, host, share
    details: dict = Field(default_factory=dict)


class PrivescCandidate(BaseModel):
    """A candidate privesc path surfaced by linpeas/winpeas/manual review.

    ``removal_command`` is how to undo any changes the exploit makes
    (e.g., remove a setuid binary, drop a file). ``None`` if the
    exploit needs no cleanup.

    ``id`` is a stable UUID per candidate so the ``PrivescAttempt``'s
    ``candidate_id`` foreign key can distinguish multiple attempts
    against the same host (Phase 4 fix wave I5 — previously the
    Post-Ex Agent set ``candidate_id = foothold.host_ip`` which
    collapsed distinct candidates on the same host into the same
    attempt record).
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    host_ip: str
    technique: str
    category: Literal["misconfig", "app_system", "kernel"]
    details: str
    confidence: float = Field(ge=0.0, le=1.0)
    exploit_command: str
    removal_command: str | None = None  # how to undo if needed


class PrivescAttempt(BaseModel):
    """A single attempted privesc, linked back to its candidate."""

    candidate_id: str
    host_ip: str
    attempted_at: datetime = Field(default_factory=datetime.utcnow)
    success: bool
    error: str | None = None
    new_context: str | None = None  # "root", "system", etc.


class PersistenceArtifact(BaseModel):
    """A persistence implant with a MANDATORY ``removal_command``.

    Spec §6.4 / §9.2 — every persistence artefact must be reversible;
    the Cleanup Agent (Phase 5) walks ``persistence_artifacts`` and
    runs ``removal_command`` on each. The ``host_ip`` field name
    resolves the spec §6.4 "host" vs. Phase 4 plan §9.2 "host_ip"
    ambiguity in favour of the Phase 4 plan (consistent with every
    other post-ex model).
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    host_ip: str
    method: Literal[
        "cron",
        "systemd",
        "bashrc",
        "ssh_authorized_keys",
        "scheduled_task",
        "registry_run",
        "service",
        "wmi_subscription",
        "dll_hijack",
    ]
    details: dict  # method-specific: cron schedule, task name, etc.
    removal_command: str  # exact command to remove this artifact
    created_at: datetime = Field(default_factory=datetime.utcnow)
    foothold_id: str


class EvasionAction(BaseModel):
    """A single defensive-evasion action (AMS bypass, ETW patch, etc.)."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    host_ip: str
    technique: Literal[
        "amsi_bypass",
        "etw_patch",
        "log_clear",
        "defender_disable",
        "process_injection",
    ]
    target: str  # what was evaded
    success: bool
    command: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ExfilEvidence(BaseModel):
    """Provenance record for an exfiltration event.

    Spec §6.8 — every exfil must be traceable to a catch-server log so
    the operator (and report) can prove what left the scope, where it
    went, and how big it was.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    method: Literal["https", "dns", "icmp", "smb"]
    source_host: str
    data_size_bytes: int
    catch_server: str
    catch_server_log_path: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
