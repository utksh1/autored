"""Phase 6 report models.

``Lesson`` mirrors the SQLite ``lessons`` table (engagement_db.py) field
for field — category values are the table's CHECK constraint set, so the
memory writer needs no translation layer. ``MitreMapping`` is one row of
the report's ATT&CK matrix; ``ReportPaths`` records where the deliverables
landed so the CLI / TUI can open them.

Typed deviation from spec §9.1: the spec declares ``lessons: list[str]``
on EngagementState, but the lessons table requires category + MITRE ID
per row, so the plan stores ``list[Lesson]`` instead.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field

LessonCategory = Literal[
    "technique_worked",
    "cve_exploited",
    "tool_issue",
    "opsec_failure",
    "misconfiguration",
    "other",
]


class Lesson(BaseModel):
    """One lessons-learned row for the engagement report.

    Field names and the ``category`` Literal match the SQLite ``lessons``
    table's CHECK constraints in ``engagement_db.py`` exactly, so Task 8
    writes rows without translation.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    category: LessonCategory
    body: str
    mitre_technique_id: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class MitreMapping(BaseModel):
    """One ATT&CK technique row in the report's MITRE table.

    ``source`` names the state collection the mapping came from
    (``"foothold"``, ``"persistence"``, ``"pivot"``, …) so Task 9's MITRE
    table and Task 16's attack graph can attribute techniques back to the
    phase that surfaced them.
    """

    technique_id: str
    technique_name: str
    tactic: str
    source: str
    detail: str


class ReportPaths(BaseModel):
    """Where the engagement's deliverables landed on disk.

    ``pdf_path`` is ``None`` when WeasyPrint is unavailable (Review Focus
    #5) — the CLI / TUI opens ``markdown_path`` in that case.
    """

    markdown_path: str
    pdf_path: str | None = None
    lessons_path: str = ""
