from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class WebApp(BaseModel):
    url: str
    host_ip: str
    port: int
    status_code: int
    title: str | None = None
    tech_stack: list[str] = Field(default_factory=list)
    web_server: str | None = None
    redirects: bool = False
    final_url: str | None = None


class DiscoveredPath(BaseModel):
    url: str
    status_code: int
    content_length: int
    depth: int = 0
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
