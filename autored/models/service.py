from __future__ import annotations

from datetime import datetime

from typing import Literal

from pydantic import BaseModel, Field


class Service(BaseModel):
    host_ip: str
    port: int
    protocol: Literal["tcp", "udp"]
    service: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
