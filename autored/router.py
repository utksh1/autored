"""Model Router for AutoRed.

Routes LLM tasks (plan_recon, synthesize_findings, etc.) to the appropriate
underlying model. Claude Sonnet 4.5 is the default for almost everything;
DeepSeek 3.2 (via the OpenAI-compatible API) is used for `second_opinion` and
`filter_blocked` only, and also serves as the fallback when the primary model
refuses to answer.

Public API
----------
- ``ROUTING_TABLE``: dict mapping task name -> model name.
- ``get_model(task)``: returns a cached ``BaseChatModel`` instance.
- ``call_with_fallback(task, prompt)``: async helper that calls the primary
  model, and on refusal falls back to DeepSeek.
- ``_is_refusal(response)``: heuristic refusal detector (exposed for tests).
"""

import os
from typing import Literal

from langchain_core.language_models import BaseChatModel

from autored.logging import get_logger

log = get_logger("router")

ModelName = Literal["claude-sonnet-4-5", "deepseek-3.2"]

# Default base URL for the OpenAI-compatible DeepSeek API.
_DEEPSEEK_DEFAULT_BASE_URL = "https://api.deepseek.com/v1"

ROUTING_TABLE: dict[str, ModelName] = {
    # Sonnet 4.5 — default for everything
    "plan_recon":          "claude-sonnet-4-5",
    "plan_exploit":        "claude-sonnet-4-5",
    "parse_nmap":          "claude-sonnet-4-5",
    "parse_nuclei":        "claude-sonnet-4-5",
    "parse_httpx":         "claude-sonnet-4-5",
    "synthesize_findings": "claude-sonnet-4-5",
    "critique_plan":       "claude-sonnet-4-5",
    "write_report":        "claude-sonnet-4-5",
    "decide_next_step":    "claude-sonnet-4-5",
    "hitl_summary":        "claude-sonnet-4-5",
    "generate_payload":    "claude-sonnet-4-5",
    "generate_command":    "claude-sonnet-4-5",
    "plan_postex":         "claude-sonnet-4-5",
    "plan_lateral":        "claude-sonnet-4-5",
    "plan_cleanup":        "claude-sonnet-4-5",
    # DeepSeek 3.2 — second opinion + filter fallback only
    "second_opinion":      "deepseek-3.2",
    "filter_blocked":      "deepseek-3.2",
}

_model_cache: dict[ModelName, BaseChatModel] = {}


def _build_sonnet() -> BaseChatModel:
    """Construct the Claude Sonnet 4.5 chat model."""
    from langchain_anthropic import ChatAnthropic

    return ChatAnthropic(
        model="claude-sonnet-4-5",
        api_key=os.environ["ANTHROPIC_API_KEY"],
        temperature=0.2,
        max_tokens=8192,
        timeout=120,
        max_retries=3,
    )


def _build_deepseek() -> BaseChatModel:
    """Construct the DeepSeek chat model (via OpenAI-compatible API)."""
    from langchain_openai import ChatOpenAI

    base_url = os.environ.get("DEEPSEEK_BASE_URL", _DEEPSEEK_DEFAULT_BASE_URL)
    return ChatOpenAI(
        model="deepseek-chat",
        api_key=os.environ["DEEPSEEK_API_KEY"],
        base_url=base_url,
        temperature=0.3,
        max_tokens=8192,
        timeout=120,
        max_retries=3,
    )


def get_model(task: str) -> BaseChatModel:
    """Get the LLM for a given task type. Caches model instances.

    Unknown tasks default to ``claude-sonnet-4-5``.
    """
    model_name = ROUTING_TABLE.get(task, "claude-sonnet-4-5")
    if model_name not in _model_cache:
        if model_name == "claude-sonnet-4-5":
            _model_cache[model_name] = _build_sonnet()
        elif model_name == "deepseek-3.2":
            _model_cache[model_name] = _build_deepseek()
        else:  # pragma: no cover - defensive, ROUTING_TABLE values are constrained
            raise ValueError(f"Unknown model name in ROUTING_TABLE: {model_name!r}")
    return _model_cache[model_name]


# Refusal markers we treat as triggers for fallback. Lowercased for matching.
_REFUSAL_MARKERS = (
    "i can't",
    "i cannot",
    "i'm not able",
    "i am not able",
    "i won't",
    "i will not",
    "as an ai",
)


def _is_refusal(response) -> bool:
    """Heuristic: detect if a model response is a refusal to comply.

    Works on any object exposing a ``.content`` attribute (LangChain
    ``AIMessage``) or falling back to ``str(response)`` for anything else.
    """
    if hasattr(response, "content") and response.content is not None:
        content = str(response.content).lower()
    else:
        content = str(response).lower()
    return any(marker in content for marker in _REFUSAL_MARKERS)


async def call_with_fallback(task: str, prompt: str) -> str:
    """Call the primary model for ``task``; on refusal, fall back to DeepSeek.

    Returns the response text. Any exception from the primary model is logged
    and re-raised — DeepSeek fallback is *only* triggered on a soft refusal,
    not on transport / API errors.
    """
    primary = get_model(task)
    try:
        response = await primary.ainvoke(prompt)
    except Exception as e:
        log.error("llm_call_failed", task=task, error=str(e))
        raise

    if _is_refusal(response):
        log.warning("primary_model_refused", task=task, falling_back=True)
        fallback = get_model("filter_blocked")
        response = await fallback.ainvoke(prompt)

    return response.content
