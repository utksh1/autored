from __future__ import annotations

from datetime import datetime

from typing import Literal

from pydantic import BaseModel, Field


class ErrorEvent(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    agent: str
    category: Literal[
        "tool", "llm", "hallucination", "hitl", "state", "roe"
    ]
    message: str
    context: dict = Field(default_factory=dict)
    recovered: bool = False
