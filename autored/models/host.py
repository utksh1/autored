from pydantic import BaseModel, Field
from datetime import datetime
from typing import Literal


class Host(BaseModel):
    ip: str
    hostname: str | None = None
    os_guess: str | None = None
    mac: str | None = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    discovered_by: str = ""
