from pydantic import BaseModel, Field
from datetime import datetime
from typing import Literal


class Service(BaseModel):
    host_ip: str
    port: int
    protocol: Literal["tcp", "udp"]
    service: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
