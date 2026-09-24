"""Phase 5 lateral-movement models (spec §9.2).

``PivotCandidate`` is the plan-side triple the Lateral Agent proposes
(credential + target + method); ``PivotRecord`` is the executed outcome;
``TunnelConfig`` records a pivot tunnel **including its teardown
command** (Phase 5 addition over spec §9.2 — the Cleanup Agent needs
it); ``SubEngagementRef`` is the parent-side link to a recursively
spawned sub-engagement; ``MovementPath`` feeds the Phase 6 attack graph.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field


class PivotCandidate(BaseModel):
    """A (credential, target_host, method) triple proposed for pivoting."""

    credential_id: str          # Secret.id of the harvested credential
    username: str               # parsed from Secret.source
    cred_type: Literal["password", "hash", "key", "token", "config", "other"]
    secret_value: str
    source_host: str            # Secret.host_ip — where the cred came from
    target_host: str
    method: Literal[
        "wmiexec", "psexec", "smbexec", "ssh", "winrm", "certipy", "crackmapexec",
    ]
    confidence: float


class PivotRecord(BaseModel):
    """An executed pivot (spec §9.2 PivotRecord)."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    target_host: str
    method: Literal[
        "wmiexec", "psexec", "smbexec", "ssh", "winrm", "certipy", "crackmapexec",
    ]
    credentials_used: list[str] = Field(default_factory=list)  # credential IDs
    success: bool = False
    new_foothold_id: str | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    needs_tunnel: bool = False


class TunnelConfig(BaseModel):
    """A pivot tunnel (spec §9.2 TunnelConfig + teardown_command).

    ``teardown_command`` is a Phase 5 addition: the Cleanup Agent (spec
    §6.6) tears tunnels down, and without a recorded command there is
    nothing deterministic to run.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    tool: Literal["chisel", "ligolo", "proxychains", "sshuttle"]
    proxy_endpoint: str
    local_port: int
    target_network: str           # CIDR reachable through tunnel
    established_at: datetime = Field(default_factory=datetime.utcnow)
    teardown_command: str = ""


class SubEngagementRef(BaseModel):
    """Parent-side reference to a recursively spawned sub-engagement."""

    sub_id: str
    target_host: str
    pivot_method: str
    status: Literal["running", "completed", "failed"]
    summary: str
    sub_state_path: str


class MovementPath(BaseModel):
    """An executed from→to movement edge (Phase 6 attack graph input)."""

    from_host: str
    to_host: str
    method: str
    credential_used: str          # credential ID
    timestamp: datetime = Field(default_factory=datetime.utcnow)
