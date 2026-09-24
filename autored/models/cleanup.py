"""Phase 5 cleanup models (spec §9.2 CleanupResult + plan structures)."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class CleanupResult(BaseModel):
    """Outcome of one removal action (spec §9.2 verbatim).

    ``success`` = the removal command executed without error;
    ``verified`` = the re-scan confirmed the artifact is gone.
    A failed removal must always surface here — never silently green
    (Review Focus #5).
    """

    artifact_id: str
    host_ip: str
    removal_command: str
    success: bool
    verified: bool
    error: str | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class HostCleanupPlan(BaseModel):
    """Per-host slice of the cleanup plan (internal to Cleanup Agent).

    Credentials (``username`` / ``password`` / ``nthash``) are the ones
    harvested during the engagement for this host — the removal
    commands are transported to the host via impacket-wmiexec (Windows)
    or ssh (Linux), which need working credentials.
    """

    host_ip: str
    artifact_ids: list[str] = Field(default_factory=list)
    removal_commands: list[str] = Field(default_factory=list)
    tunnel_teardowns: list[str] = Field(default_factory=list)
    temp_files: list[str] = Field(default_factory=list)
    transport: Literal["impacket_wmiexec", "ssh"] = "impacket_wmiexec"
    username: str = ""
    password: str = ""
    nthash: str = ""


class CleanupPlan(BaseModel):
    """Whole-engagement cleanup plan, grouped per host."""

    by_host: list[HostCleanupPlan] = Field(default_factory=list)
    total_actions: int = 0
