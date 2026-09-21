from pydantic import BaseModel, Field
from datetime import datetime
from typing import Literal


class ErrorEvent(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    agent: str
    category: Literal["tool", "llm", "hallucination", "hitl", "state", "roe"]
    message: str
    context: dict = Field(default_factory=dict)
    recovered: bool = False
