from pydantic import BaseModel, Field
from datetime import datetime


class DiscoveredPath(BaseModel):
    url: str
    status_code: int
    content_length: int
    depth: int = 0
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
