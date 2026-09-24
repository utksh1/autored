from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class Host(BaseModel):
    ip: str
    hostname: str | None = None
    os_guess: str | None = None
    mac: str | None = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    discovered_by: str = ""
