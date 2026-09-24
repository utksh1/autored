"""Unit tests for ExecSummaryWriter (Phase 6 Task 4)."""
import json
from unittest.mock import AsyncMock, MagicMock, patch

from autored.subagents.execsummarywriter import (
    _parse_summary_dict,
    _template_exec_summary,
    execsummarywriter_subagent,
)


def _summary() -> dict:
    return {
        "engagement_id": "e1",
        "target": "10.10.10.5",
        "operator": "tester",
        "duration_min": 42.0,
        "hosts": 1,
        "services": 5,
        "findings": 3,
        "findings_by_severity": {"critical": 1, "high": 1, "medium": 1, "low": 0, "info": 0},
        "footholds": 1,
        "privesc_successes": 1,
        "pivots": 1,
        "sub_engagements": 1,
        "cleanup_all_verified": True,
        "outcome": "full chain achieved",
    }


def test_parse_summary_dict_round_trip():
    parsed = _parse_summary_dict(json.dumps(_summary()))
    assert parsed["engagement_id"] == "e1"
    assert _parse_summary_dict(_summary())["footholds"] == 1  # dict passthrough


def test_template_renders_all_key_facts():
    md = _template_exec_summary(_summary())
    assert "10.10.10.5" in md
    assert "1 host" in md or "1 hosts" in md
    assert "1 critical" in md
    assert "full chain achieved" in md
    assert "cleanup" in md.lower()


async def test_llm_path_returns_model_content():
    mock_response = MagicMock()
    mock_response.content = "## Executive Summary\n\nAutoRed achieved a full chain."
    with patch("autored.subagents.execsummarywriter.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=mock_response)
        mock_get_model.return_value = mock_model

        output = await execsummarywriter_subagent.ainvoke({
            "engagement_summary": json.dumps(_summary()),
            "engagement_id": "e1",
        })
    assert output.summary_markdown.startswith("## Executive Summary")
    assert output.used_fallback is False


async def test_llm_failure_falls_back_to_template():
    """Review Focus #3 — API failure must never lose the deliverable."""
    with patch("autored.subagents.execsummarywriter.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(side_effect=RuntimeError("503 service unavailable"))
        mock_get_model.return_value = mock_model

        output = await execsummarywriter_subagent.ainvoke({
            "engagement_summary": json.dumps(_summary()),
            "engagement_id": "e1",
        })
    assert output.used_fallback is True
    assert "10.10.10.5" in output.summary_markdown


async def test_llm_refusal_falls_back_to_template():
    mock_response = MagicMock()
    mock_response.content = "I cannot assist with this request."
    with patch("autored.subagents.execsummarywriter.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=mock_response)
        mock_get_model.return_value = mock_model

        output = await execsummarywriter_subagent.ainvoke({
            "engagement_summary": json.dumps(_summary()),
            "engagement_id": "e1",
        })
    assert output.used_fallback is True


async def test_empty_llm_response_falls_back():
    mock_response = MagicMock()
    mock_response.content = ""
    with patch("autored.subagents.execsummarywriter.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=mock_response)
        mock_get_model.return_value = mock_model

        output = await execsummarywriter_subagent.ainvoke({
            "engagement_summary": json.dumps(_summary()),
            "engagement_id": "e1",
        })
    assert output.used_fallback is True


def test_template_renders_partial_cleanup_warning_when_unverified():
    s = _summary()
    s["cleanup_all_verified"] = False
    md = _template_exec_summary(s)
    assert "could not be verified" in md.lower()
