"""Unit tests for LessonExtractor (Phase 6 Task 6)."""
import json
from unittest.mock import AsyncMock, MagicMock, patch

from autored.subagents.lessonextractor import (
    _fallback_lessons,
    _validate_lesson_payload,
    lessonextractor_subagent,
)


def _summary() -> dict:
    return {
        "footholds": [{"method": "ms17_010", "host_ip": "10.0.0.5", "username": "system"}],
        "pivots": [{"method": "wmiexec", "target_host": "10.0.0.8", "success": True}],
        "unverified_cleanups": [{"host_ip": "10.0.0.8", "removal_command": "schtasks /delete ..."}],
        "errors": [],
    }


def test_validate_keeps_valid_lessons():
    payload = [
        {"category": "technique_worked", "body": "EternalBlue worked", "mitre_technique_id": "T1210"},
        {"category": "cve_exploited", "body": "CVE-2017-0144 exploited"},
    ]
    lessons = _validate_lesson_payload(payload)
    assert len(lessons) == 2
    assert lessons[0].mitre_technique_id == "T1210"


def test_validate_drops_invalid_category():
    payload = [
        {"category": "amazing_insight", "body": "junk"},
        {"category": "tool_issue", "body": "nmap crashed"},
    ]
    lessons = _validate_lesson_payload(payload)
    assert len(lessons) == 1
    assert lessons[0].category == "tool_issue"


def test_validate_nulls_unknown_mitre_id():
    """LLM-invented technique IDs are stripped, body survives."""
    payload = [
        {"category": "technique_worked", "body": "worked",
         "mitre_technique_id": "T9999.999"},
    ]
    lessons = _validate_lesson_payload(payload)
    assert len(lessons) == 1
    assert lessons[0].mitre_technique_id is None
    assert lessons[0].body == "worked"


def test_validate_drops_empty_body():
    payload = [
        {"category": "tool_issue", "body": "   "},
        {"category": "other", "body": "real lesson"},
    ]
    lessons = _validate_lesson_payload(payload)
    assert len(lessons) == 1
    assert lessons[0].body == "real lesson"


def test_validate_drops_non_dict_rows():
    payload = ["not a dict", 42, None, {"category": "other", "body": "ok"}]
    lessons = _validate_lesson_payload(payload)
    assert len(lessons) == 1
    assert lessons[0].body == "ok"


def test_fallback_lessons_from_outcomes():
    lessons = _fallback_lessons(_summary())
    categories = [l.category for l in lessons]
    assert categories.count("technique_worked") == 2  # foothold + pivot
    assert categories.count("tool_issue") == 1        # unverified cleanup
    bodies = " ".join(l.body for l in lessons)
    assert "ms17_010" in bodies
    assert "wmiexec" in bodies


def test_fallback_lessons_skips_failed_pivots():
    summary = {
        "footholds": [],
        "pivots": [{"method": "ssh", "target_host": "10.0.0.9", "success": False}],
        "unverified_cleanups": [],
        "errors": [],
    }
    lessons = _fallback_lessons(summary)
    assert lessons == []


async def test_llm_path_parses_json_lessons():
    llm_json = json.dumps([
        {"category": "technique_worked", "body": "wmiexec with NTLM hash worked on GoAD",
         "mitre_technique_id": "T1047"},
    ])
    mock_response = MagicMock()
    mock_response.content = llm_json
    with patch("autored.subagents.lessonextractor.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=mock_response)
        mock_get_model.return_value = mock_model

        output = await lessonextractor_subagent.ainvoke({
            "engagement_summary": json.dumps(_summary()), "engagement_id": "e1",
        })
    assert len(output.lessons) == 1
    assert output.lessons[0].category == "technique_worked"


async def test_llm_path_tolerates_code_fences():
    llm_json = '```json\n[\n{"category": "other", "body": "fenced"}]\n```'
    mock_response = MagicMock()
    mock_response.content = llm_json
    with patch("autored.subagents.lessonextractor.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=mock_response)
        mock_get_model.return_value = mock_model

        output = await lessonextractor_subagent.ainvoke({
            "engagement_summary": json.dumps(_summary()), "engagement_id": "e1",
        })
    assert len(output.lessons) == 1
    assert output.lessons[0].body == "fenced"


async def test_llm_failure_falls_back():
    with patch("autored.subagents.lessonextractor.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(side_effect=RuntimeError("429"))
        mock_get_model.return_value = mock_model

        output = await lessonextractor_subagent.ainvoke({
            "engagement_summary": json.dumps(_summary()), "engagement_id": "e1",
        })
    assert len(output.lessons) >= 2  # deterministic fallback
    assert all(l.category in {
        "technique_worked", "cve_exploited", "tool_issue",
        "opsec_failure", "misconfiguration", "other",
    } for l in output.lessons)


async def test_llm_garbage_json_falls_back():
    mock_response = MagicMock()
    mock_response.content = "not json at all {{{"
    with patch("autored.subagents.lessonextractor.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=mock_response)
        mock_get_model.return_value = mock_model

        output = await lessonextractor_subagent.ainvoke({
            "engagement_summary": json.dumps(_summary()), "engagement_id": "e1",
        })
    assert len(output.lessons) >= 2  # fallback engaged, no crash


async def test_llm_refusal_falls_back():
    """Review Focus #3 — refusal must trigger the deterministic fallback."""
    mock_response = MagicMock()
    mock_response.content = "I cannot assist with this request."
    with patch("autored.subagents.lessonextractor.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=mock_response)
        mock_get_model.return_value = mock_model

        output = await lessonextractor_subagent.ainvoke({
            "engagement_summary": json.dumps(_summary()), "engagement_id": "e1",
        })
    assert len(output.lessons) >= 2  # fallback engaged


async def test_llm_empty_content_falls_back():
    mock_response = MagicMock()
    mock_response.content = ""
    with patch("autored.subagents.lessonextractor.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=mock_response)
        mock_get_model.return_value = mock_model

        output = await lessonextractor_subagent.ainvoke({
            "engagement_summary": json.dumps(_summary()), "engagement_id": "e1",
        })
    assert len(output.lessons) >= 2  # fallback engaged, no crash
