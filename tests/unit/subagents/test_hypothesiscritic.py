"""Tests for the HypothesisCritic sub-agent (Phase 2, Task 8).

Verifies that ``hypothesiscritic_subagent`` invokes the DeepSeek
second-opinion model (via ``get_model("second_opinion")``), parses the
JSON critique response (with markdown code-fence stripping), and degrades
gracefully on (a) malformed JSON, (b) refusal (Phase 0 T9 centralised
``_is_refusal`` from the router).
"""

from unittest.mock import AsyncMock, patch

import pytest

from autored.subagents.hypothesiscritic import (
    CritiqueOutput,
    _parse_critique_response,
    hypothesiscritic_subagent,
)


def _mock_response(content: str):
    """Build a minimal duck-typed response object exposing ``.content``."""
    return type("MockResp", (), {"content": content})()


@pytest.mark.asyncio
async def test_critic_returns_critique_for_each_hypothesis():
    fake_response = _mock_response(
        """```json
    {
      "critique": [
        {"rank": 1, "issues": ["CVE is real but version mismatch"], "verdict": "needs_revision", "verdict_reason": "target version not affected"},
        {"rank": 2, "issues": [], "verdict": "sound", "verdict_reason": "all checks pass"}
      ]
    }
    ```"""
    )

    hypotheses = [
        {"rank": 1, "target": "10.10.10.5", "technique": "t1", "cve": "CVE-2017-0144"},
        {"rank": 2, "target": "10.10.10.5", "technique": "t2", "cve": "CVE-2014-6271"},
    ]

    with patch("autored.subagents.hypothesiscritic.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=fake_response)
        mock_get_model.return_value = mock_model

        result = await hypothesiscritic_subagent.ainvoke(
            {
                "hypotheses": hypotheses,
                "engagement_id": "test-eng",
            }
        )

    assert isinstance(result, CritiqueOutput)
    assert len(result.critique) == 2
    assert result.critique[0]["verdict"] == "needs_revision"
    assert result.critique[1]["verdict"] == "sound"


@pytest.mark.asyncio
async def test_critic_flags_hallucinated_cve():
    """Review Focus: hallucinated CVE must be flagged."""
    fake_response = _mock_response(
        """```json
    {
      "critique": [
        {"rank": 1, "issues": ["CVE-2099-9999 does not exist in NVD"], "verdict": "discard", "verdict_reason": "hallucinated CVE"}
      ]
    }
    ```"""
    )

    hypotheses = [
        {"rank": 1, "target": "x", "technique": "x", "cve": "CVE-2099-9999"},
    ]

    with patch("autored.subagents.hypothesiscritic.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=fake_response)
        mock_get_model.return_value = mock_model

        result = await hypothesiscritic_subagent.ainvoke(
            {
                "hypotheses": hypotheses,
                "engagement_id": "test-eng",
            }
        )

    assert result.critique[0]["verdict"] == "discard"
    assert (
        "hallucinated" in result.critique[0]["verdict_reason"].lower()
        or "does not exist" in result.critique[0]["issues"][0].lower()
    )


@pytest.mark.asyncio
async def test_critic_handles_malformed_response():
    fake_response = _mock_response("This is not JSON")

    hypotheses = [{"rank": 1, "target": "x", "technique": "x", "cve": "CVE-2014-6271"}]

    with patch("autored.subagents.hypothesiscritic.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=fake_response)
        mock_get_model.return_value = mock_model

        result = await hypothesiscritic_subagent.ainvoke(
            {
                "hypotheses": hypotheses,
                "engagement_id": "test-eng",
            }
        )

    # Should return empty critique, not crash
    assert result.critique == []


@pytest.mark.asyncio
async def test_critic_handles_empty_hypotheses_short_circuit():
    """No hypotheses → no LLM call at all (short-circuit before get_model)."""
    with patch("autored.subagents.hypothesiscritic.get_model") as mock_get_model:
        result = await hypothesiscritic_subagent.ainvoke(
            {
                "hypotheses": [],
                "engagement_id": "test-eng",
            }
        )
    mock_get_model.assert_not_called()
    assert isinstance(result, CritiqueOutput)
    assert result.critique == []


@pytest.mark.asyncio
async def test_critic_returns_empty_on_refusal():
    """Review Focus (Phase 0 T9): when DeepSeek declines rather than producing
    JSON, the centralised ``_is_refusal`` heuristic (from the router) detects
    the refusal and the sub-agent returns an empty critique rather than
    feeding prose into the JSON parser (which would either crash or yield
    garbage verdicts the downstream Vuln Agent would trust).

    Without this fix, a DeepSeek refusal like "I can't help with that"
    would propagate through to ``_parse_critique_response`` which would
    raise JSONDecodeError and the sub-agent would surface a non-empty
    error to the Vuln Agent's self-critique loop.
    """
    fake_response = _mock_response(
        "I can't help with that — this looks like an offensive security request."
    )

    hypotheses = [
        {"rank": 1, "target": "x", "technique": "x", "cve": "CVE-2014-6271"},
    ]

    with patch("autored.subagents.hypothesiscritic.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=fake_response)
        mock_get_model.return_value = mock_model

        result = await hypothesiscritic_subagent.ainvoke(
            {
                "hypotheses": hypotheses,
                "engagement_id": "test-eng",
            }
        )

    assert isinstance(result, CritiqueOutput)
    assert result.critique == []


def test_parse_critique_response_pure_function_unit():
    """Direct unit tests on the JSON/markdown parser (no LLM mock)."""
    # 1. Markdown-fenced JSON
    fenced = """```json
    {"critique": [{"rank": 1, "verdict": "sound", "issues": []}]}
    ```"""
    out = _parse_critique_response(fenced)
    assert len(out) == 1
    assert out[0]["verdict"] == "sound"

    # 2. Plain JSON (no fence)
    plain = '{"critique": [{"rank": 1, "verdict": "discard", "issues": ["x"]}]}'
    out = _parse_critique_response(plain)
    assert len(out) == 1
    assert out[0]["verdict"] == "discard"

    # 3. Missing "critique" key
    no_key = '{"something_else": []}'
    assert _parse_critique_response(no_key) == []

    # 4. Top-level JSON list (not dict)
    assert _parse_critique_response("[1, 2, 3]") == []

    # 5. Total garbage
    assert _parse_critique_response("not even close to json") == []

    # 6. Empty string
    assert _parse_critique_response("") == []

    # 7. critique present but wrong shape (string, not list)
    bad_shape = '{"critique": "not a list"}'
    assert _parse_critique_response(bad_shape) == []
