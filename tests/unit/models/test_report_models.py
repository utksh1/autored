"""Unit tests for Phase 6 report models (spec §9.2 + plan additions)."""
from datetime import datetime

import pytest
from pydantic import ValidationError

from autored.models.report import Lesson, MitreMapping, ReportPaths


def test_lesson_fields_match_sqlite_lessons_table():
    """Category values must be exactly the SQLite CHECK constraint set."""
    lesson = Lesson(category="technique_worked", body="EternalBlue worked on SMB-exposed host")
    assert lesson.id  # uuid default factory
    assert lesson.mitre_technique_id is None
    assert isinstance(lesson.created_at, datetime)


def test_lesson_accepts_every_category():
    for category in (
        "technique_worked", "cve_exploited", "tool_issue",
        "opsec_failure", "misconfiguration", "other",
    ):
        assert Lesson(category=category, body="x").category == category


def test_lesson_rejects_unknown_category():
    with pytest.raises(ValidationError):
        Lesson(category="great_success", body="x")


def test_mitre_mapping_fields():
    m = MitreMapping(
        technique_id="T1053.005",
        technique_name="Scheduled Task/Job: Scheduled Task",
        tactic="persistence",
        source="persistence",
        detail="scheduled_task on 192.168.56.22",
    )
    assert m.technique_id.startswith("T")
    assert m.tactic == "persistence"


def test_report_paths_pdf_optional():
    p = ReportPaths(
        markdown_path="engagements/e1/report.md",
        lessons_path="engagements/e1/lessons.json",
    )
    assert p.pdf_path is None  # weasyprint unavailable → None, never raised
    p2 = ReportPaths(
        markdown_path="engagements/e1/report.md",
        pdf_path="engagements/e1/report.pdf",
        lessons_path="engagements/e1/lessons.json",
    )
    assert p2.pdf_path.endswith(".pdf")
