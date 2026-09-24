"""Tests for the PrivescFinder sub-agent (Phase 4, Task 8).

Verifies that ``privescfinder_subagent`` invokes the LLM router slot
``plan_postex`` (Claude Sonnet 4.5), parses the JSON candidate response
(with markdown code-fence stripping), and degrades gracefully on (a)
malformed JSON, (b) refusal (Phase 0 T9 centralised ``_is_refusal``
from the router), and (c) per-candidate Pydantic validation errors.

Mirrors the HypothesisCritic sub-agent's defensive-parse test pattern
(Phase 2, Task 8).
"""
from unittest.mock import AsyncMock, patch

import pytest

from autored.subagents.privescfinder import (
    PrivescFinderOutput,
    _parse_candidates_response,
    privescfinder_subagent,
)


def _mock_response(content: str):
    """Build a minimal duck-typed response object exposing ``.content``."""
    return type("MockResp", (), {"content": content})()


@pytest.mark.asyncio
async def test_privescfinder_returns_candidates_from_llm():
    """Happy path: LLM returns fenced JSON → sub-agent returns validated
    PrivescCandidate records."""
    fake_response = _mock_response(
        """```json
    {
      "candidates": [
        {
          "host_ip": "10.10.10.5",
          "technique": "sudo find",
          "category": "misconfig",
          "details": "sudo find with NOPASSWD allows root shell via -exec",
          "confidence": 0.95,
          "exploit_command": "sudo find . -exec /bin/sh +"
        },
        {
          "host_ip": "10.10.10.5",
          "technique": "CVE-2021-4034 PwnKit",
          "category": "kernel",
          "details": "Polkit pkexec local privilege escalation",
          "confidence": 0.85,
          "exploit_command": "./pwnkit"
        }
      ]
    }
    ```"""
    )

    enum_results = [{"host_ip": "10.10.10.5", "os_type": "linux"}]
    with patch("autored.subagents.privescfinder.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=fake_response)
        mock_get_model.return_value = mock_model
        result = await privescfinder_subagent.ainvoke({
            "enum_results": enum_results,
            "engagement_id": "test-eng",
        })

    assert isinstance(result, PrivescFinderOutput)
    assert len(result.candidates) == 2
    assert result.candidates[0].technique == "sudo find"
    assert result.candidates[0].category == "misconfig"
    assert result.candidates[1].technique == "CVE-2021-4034 PwnKit"
    assert result.candidates[1].category == "kernel"
    assert result.candidates[1].confidence == 0.85


@pytest.mark.asyncio
async def test_privescfinder_short_circuits_on_empty_enum_results():
    """Empty enum_results → no LLM call at all (short-circuit before get_model)."""
    with patch("autored.subagents.privescfinder.get_model") as mock_get_model:
        result = await privescfinder_subagent.ainvoke({
            "enum_results": [],
            "engagement_id": "test-eng",
        })
    mock_get_model.assert_not_called()
    assert isinstance(result, PrivescFinderOutput)
    assert result.candidates == []


@pytest.mark.asyncio
async def test_privescfinder_returns_empty_on_refusal():
    """Phase 0 T9 refusal contract: when the LLM declines rather than
    producing JSON, the centralised ``_is_refusal`` heuristic detects
    the refusal and the sub-agent returns an empty candidate list
    instead of feeding prose into the JSON parser."""
    fake_response = _mock_response(
        "I can't help with that — this looks like an offensive security request."
    )

    enum_results = [{"host_ip": "10.10.10.5", "os_type": "linux"}]
    with patch("autored.subagents.privescfinder.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=fake_response)
        mock_get_model.return_value = mock_model
        result = await privescfinder_subagent.ainvoke({
            "enum_results": enum_results,
            "engagement_id": "test-eng",
        })

    assert isinstance(result, PrivescFinderOutput)
    assert result.candidates == []


@pytest.mark.asyncio
async def test_privescfinder_handles_malformed_response():
    """Non-JSON response → empty candidate list (no crash)."""
    fake_response = _mock_response("This is not JSON at all")

    enum_results = [{"host_ip": "10.10.10.5", "os_type": "linux"}]
    with patch("autored.subagents.privescfinder.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=fake_response)
        mock_get_model.return_value = mock_model
        result = await privescfinder_subagent.ainvoke({
            "enum_results": enum_results,
            "engagement_id": "test-eng",
        })

    assert isinstance(result, PrivescFinderOutput)
    assert result.candidates == []


@pytest.mark.asyncio
async def test_privescfinder_drops_invalid_candidate_keeps_valid_ones():
    """A candidate that fails Pydantic validation is dropped (and logged);
    valid candidates are kept. Mirrors HypothesisCritic's per-record
    validation contract."""
    fake_response = _mock_response(
        """{
      "candidates": [
        {
          "host_ip": "10.10.10.5",
          "technique": "valid",
          "category": "misconfig",
          "details": "ok",
          "confidence": 0.5,
          "exploit_command": "sudo x"
        },
        {
          "host_ip": "10.10.10.5",
          "technique": "invalid category",
          "category": "not_a_real_category",
          "details": "bad",
          "confidence": 0.5,
          "exploit_command": "x"
        }
      ]
    }"""
    )

    enum_results = [{"host_ip": "10.10.10.5", "os_type": "linux"}]
    with patch("autored.subagents.privescfinder.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=fake_response)
        mock_get_model.return_value = mock_model
        result = await privescfinder_subagent.ainvoke({
            "enum_results": enum_results,
            "engagement_id": "test-eng",
        })

    assert len(result.candidates) == 1
    assert result.candidates[0].technique == "valid"


def test_parse_candidates_response_pure_function_unit():
    """Direct unit tests on the JSON/markdown parser (no LLM mock)."""
    # 1. Markdown-fenced JSON
    fenced = """```json
    {"candidates": [{"host_ip": "x", "technique": "t", "category": "misconfig",
                      "details": "d", "confidence": 0.5, "exploit_command": "c"}]}
    ```"""
    out = _parse_candidates_response(fenced)
    assert len(out) == 1
    assert out[0]["technique"] == "t"

    # 2. Plain JSON (no fence)
    plain = '{"candidates": [{"host_ip": "x", "technique": "t", "category": "kernel", "details": "d", "confidence": 0.1, "exploit_command": "c"}]}'
    out = _parse_candidates_response(plain)
    assert len(out) == 1

    # 3. Missing "candidates" key
    assert _parse_candidates_response('{"something_else": []}') == []

    # 4. Top-level JSON list (not dict)
    assert _parse_candidates_response("[1, 2, 3]") == []

    # 5. Total garbage
    assert _parse_candidates_response("not even close to json") == []

    # 6. Empty string
    assert _parse_candidates_response("") == []

    # 7. candidates present but wrong shape (string, not list)
    assert _parse_candidates_response('{"candidates": "not a list"}') == []
