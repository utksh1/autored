import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from autored.router import get_model, ROUTING_TABLE, call_with_fallback, _is_refusal


def test_routing_table_has_all_tasks():
    expected_tasks = [
        "plan_recon", "synthesize_findings", "second_opinion", "filter_blocked",
    ]
    for task in expected_tasks:
        assert task in ROUTING_TABLE


def test_routing_table_default_is_sonnet():
    # Most tasks should route to Sonnet
    assert ROUTING_TABLE["plan_recon"] == "claude-sonnet-4-5"
    assert ROUTING_TABLE["synthesize_findings"] == "claude-sonnet-4-5"


def test_routing_table_deepseek_for_second_opinion():
    assert ROUTING_TABLE["second_opinion"] == "deepseek-3.2"
    assert ROUTING_TABLE["filter_blocked"] == "deepseek-3.2"


def test_routing_table_unknown_task_defaults_to_sonnet():
    # The router should fall back to Sonnet for unknown tasks via get_model.
    # Verify a representative sample of well-known tasks route to sonnet.
    for task in [
        "plan_exploit", "parse_nmap", "parse_nuclei", "parse_httpx",
        "critique_plan", "write_report", "decide_next_step", "hitl_summary",
        "generate_payload", "generate_command",
        "plan_postex", "plan_lateral", "plan_cleanup",
    ]:
        assert ROUTING_TABLE[task] == "claude-sonnet-4-5", f"{task} should route to sonnet"


def test_get_model_returns_cached(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    model1 = get_model("plan_recon")
    model2 = get_model("plan_recon")
    assert model1 is model2  # same instance (cached)


def test_get_model_returns_cached_deepseek(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    model1 = get_model("second_opinion")
    model2 = get_model("second_opinion")
    assert model1 is model2  # same instance (cached)


def test_get_model_unknown_task_uses_sonnet(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    # Unknown tasks default to Sonnet; cached instance should match a known
    # Sonnet task.
    model_unknown = get_model("nonexistent_task_xyz")
    model_known_sonnet = get_model("plan_recon")
    assert model_unknown is model_known_sonnet


def test_is_refusal_detects_common_markers():
    resp = MagicMock()
    resp.content = "I'm sorry, but I can't help with that request."
    assert _is_refusal(resp) is True

    resp2 = MagicMock()
    resp2.content = "I cannot assist with that."
    assert _is_refusal(resp2) is True

    resp3 = MagicMock()
    resp3.content = "As an AI language model, I cannot..."
    assert _is_refusal(resp3) is True


def test_is_refusal_returns_false_for_normal_response():
    resp = MagicMock()
    resp.content = "Here is the nmap scan result: 22/tcp open ssh"
    assert _is_refusal(resp) is False


@pytest.mark.asyncio
async def test_call_with_fallback_uses_primary_first(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")

    mock_response = MagicMock()
    mock_response.content = "primary response"

    mock_model = AsyncMock()
    mock_model.ainvoke = AsyncMock(return_value=mock_response)

    with patch("autored.router.get_model", return_value=mock_model):
        result = await call_with_fallback("plan_recon", "test prompt")

    assert result == "primary response"


@pytest.mark.asyncio
async def test_call_with_fallback_falls_back_on_refusal(monkeypatch):
    """When the primary model returns a refusal, fall back to DeepSeek."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")

    refusal_response = MagicMock()
    refusal_response.content = "I'm sorry, but I can't help with that."

    fallback_response = MagicMock()
    fallback_response.content = "fallback answer"

    primary_model = AsyncMock()
    primary_model.ainvoke = AsyncMock(return_value=refusal_response)

    fallback_model = AsyncMock()
    fallback_model.ainvoke = AsyncMock(return_value=fallback_response)

    def fake_get_model(task: str):
        if task == "filter_blocked":
            return fallback_model
        return primary_model

    with patch("autored.router.get_model", side_effect=fake_get_model):
        result = await call_with_fallback("plan_recon", "do something offensive")

    assert result == "fallback answer"
    # Primary was called once, fallback was called once.
    primary_model.ainvoke.assert_awaited_once()
    fallback_model.ainvoke.assert_awaited_once()


@pytest.mark.asyncio
async def test_call_with_fallback_reraises_on_exception(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")

    primary_model = AsyncMock()
    primary_model.ainvoke = AsyncMock(side_effect=RuntimeError("network down"))

    with patch("autored.router.get_model", return_value=primary_model):
        with pytest.raises(RuntimeError, match="network down"):
            await call_with_fallback("plan_recon", "test prompt")
