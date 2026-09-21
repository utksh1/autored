"""Post-Ex (Phase 4) Pydantic models.

Eight models that capture the structured state produced by the six
Post-Ex sub-activities (enumeration, privesc, persistence, evasion,
exfil, cleanup prep):

* ``User``                       — local account discovered on a foothold host.
* ``Secret``                     — credential / config / key harvested from a host.
* ``Trust``                      — domain / SSH / NFS / SMB / Kerberos trust link.
* ``PrivescCandidate``           — a privilege-escalation path identified by the
                                   PrivescFinder sub-agent.
* ``PrivescAttempt``             — the result of actually executing a candidate.
* ``PersistenceArtifact``        — a persistence foothold installed on a host
                                   (Review Focus #3: ``removal_command`` is
                                   required — the Phase 5 Cleanup Agent runs
                                   it verbatim).
* ``EvasionAction``              — a defense-evasion action (AMSI bypass, ETW
                                   patch, log clear, defender disable, process
                                   injection).
* ``ExfilEvidence``              — proof of a successful exfiltration (method,
                                   size, catch-server log path).

These mirror the spec §9.2 table and are persisted on the
``EngagementState`` via ``default_factory=list`` so existing Phase 1-3
tests do not need to know about Phase 4.
"""
from datetime import datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field


class User(BaseModel):
    """A local account enumerated on a foothold host."""

    host_ip: str
    username: str
    uid: str | None = None  # Linux UID or Windows SID
    groups: list[str] = Field(default_factory=list)
    is_admin: bool = False
    is_service_account: bool = False


class Secret(BaseModel):
    """A credential / key / config / token harvested from a host."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    host_ip: str
    secret_type: Literal["password", "hash", "key", "token", "config", "other"]
    secret_value: str
    source: str  # file path, registry key, etc.
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class Trust(BaseModel):
    """A trust relationship (AD domain, SSH, NFS, SMB, Kerberos) on a host."""

    host_ip: str
    trust_type: Literal["ad_domain", "ssh_trust", "nfs_export", "smb_share", "kerberos"]
    target: str  # domain, host, share
    details: dict = Field(default_factory=dict)


class PrivescCandidate(BaseModel):
    """A privilege-escalation path identified by the PrivescFinder sub-agent."""

    host_ip: str
    technique: str
    category: Literal["misconfig", "app_system", "kernel"]
    details: str
    confidence: float = Field(ge=0.0, le=1.0)
    exploit_command: str
    removal_command: str | None = None  # how to undo if needed


class PrivescAttempt(BaseModel):
    """The result of actually executing a PrivescCandidate."""

    candidate_id: str
    host_ip: str
    attempted_at: datetime = Field(default_factory=datetime.utcnow)
    success: bool
    error: str | None = None
    new_context: str | None = None  # "root", "system", etc.


class PersistenceArtifact(BaseModel):
    """A persistence foothold installed on a host.

    Review Focus #3: ``removal_command`` is REQUIRED. The Phase 5
    Cleanup Agent runs it verbatim to tear the artifact down.
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
    """A defense-evasion action executed against a host."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    host_ip: str
    technique: Literal[
        "amsi_bypass", "etw_patch", "log_clear", "defender_disable", "process_injection"
    ]
    target: str  # what was evaded
    success: bool
    command: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ExfilEvidence(BaseModel):
    """Proof of a successful data exfiltration."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    method: Literal["https", "dns", "icmp", "smb"]
    source_host: str
    data_size_bytes: int
    catch_server: str
    catch_server_log_path: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
