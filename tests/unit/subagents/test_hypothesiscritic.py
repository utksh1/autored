# tests/unit/subagents/test_hypothesiscritic.py
import pytest
from unittest.mock import AsyncMock, patch
from autored.subagents.hypothesiscritic import hypothesiscritic_subagent, CritiqueOutput

@pytest.mark.asyncio
async def test_critic_returns_critique_for_each_hypothesis():
    fake_response = type("MockResp", (), {"content": """```json
    {
      "critique": [
        {"rank": 1, "issues": ["CVE is real but version mismatch"], "verdict": "needs_revision", "verdict_reason": "target version not affected"},
        {"rank": 2, "issues": [], "verdict": "sound", "verdict_reason": "all checks pass"}
      ]
    }
    ```"""})()

    hypotheses = [
        {"rank": 1, "target": "10.10.10.5", "technique": "t1", "cve": "CVE-2017-0144"},
        {"rank": 2, "target": "10.10.10.5", "technique": "t2", "cve": "CVE-2014-6271"},
    ]

    with patch("autored.subagents.hypothesiscritic.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=fake_response)
        mock_get_model.return_value = mock_model

        result = await hypothesiscritic_subagent.ainvoke({
            "hypotheses": hypotheses,
            "engagement_id": "test-eng",
        })

    assert isinstance(result, CritiqueOutput)
    assert len(result.critique) == 2
    assert result.critique[0]["verdict"] == "needs_revision"
    assert result.critique[1]["verdict"] == "sound"

@pytest.mark.asyncio
async def test_critic_flags_hallucinated_cve():
    """Review Focus: hallucinated CVE must be flagged."""
    fake_response = type("MockResp", (), {"content": """```json
    {
      "critique": [
        {"rank": 1, "issues": ["CVE-2099-9999 does not exist in NVD"], "verdict": "discard", "verdict_reason": "hallucinated CVE"}
      ]
    }
    ```"""})()

    hypotheses = [
        {"rank": 1, "target": "x", "technique": "x", "cve": "CVE-2099-9999"},
    ]

    with patch("autored.subagents.hypothesiscritic.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=fake_response)
        mock_get_model.return_value = mock_model

        result = await hypothesiscritic_subagent.ainvoke({
            "hypotheses": hypotheses,
            "engagement_id": "test-eng",
        })

    assert result.critique[0]["verdict"] == "discard"
    assert "hallucinated" in result.critique[0]["verdict_reason"].lower() or "does not exist" in result.critique[0]["issues"][0].lower()

@pytest.mark.asyncio
async def test_critic_handles_malformed_response():
    fake_response = type("MockResp", (), {"content": "This is not JSON"})()

    hypotheses = [{"rank": 1, "target": "x", "technique": "x", "cve": "CVE-2014-6271"}]

    with patch("autored.subagents.hypothesiscritic.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=fake_response)
        mock_get_model.return_value = mock_model

        result = await hypothesiscritic_subagent.ainvoke({
            "hypotheses": hypotheses,
            "engagement_id": "test-eng",
        })

    # Should return empty critique, not crash
    assert result.critique == []
