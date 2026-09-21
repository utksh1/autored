"""Test fixtures for the model router.

Why this conftest exists
------------------------
The pinned ``anthropic==0.39.0`` SDK constructs its internal ``anthropic.Client``
eagerly inside ``ChatAnthropic.__post_init__``. That client passes ``proxies=None``
to ``httpx.Client`` — but the installed ``httpx==0.28.1`` removed the ``proxies``
keyword, so simply *instantiating* ``ChatAnthropic`` raises ``TypeError``.

The router tests need to verify caching and unknown-task fallback behaviour by
actually invoking ``get_model()`` (and therefore the real ``_build_sonnet`` /
``_build_deepseek`` builders). We don't want to make real API calls — we just
need a stand-in object. So we patch the *constructor classes*
(``langchain_anthropic.ChatAnthropic`` and ``langchain_openai.ChatOpenAI``) to
return lightweight ``MagicMock`` instances. This exercises the router's own
logic (env-var reading, parameter passing, caching) without touching httpx.

Tests that already mock ``get_model`` itself (the ``call_with_fallback`` tests)
are unaffected because they never reach the builders.
"""

from unittest.mock import MagicMock

import pytest


@pytest.fixture(autouse=True)
def _mock_model_constructors(monkeypatch):
    """Replace ChatAnthropic / ChatOpenAI constructors with MagicMock factories.

    Each call returns a fresh ``MagicMock`` instance so that caching behaviour
    in ``get_model()`` can be verified (the first call's mock is cached and
    returned on subsequent calls for the same model name).
    """
    import langchain_anthropic
    import langchain_openai

    monkeypatch.setattr(
        langchain_anthropic, "ChatAnthropic",
        lambda *args, **kwargs: MagicMock(name="ChatAnthropic"),
    )
    monkeypatch.setattr(
        langchain_openai, "ChatOpenAI",
        lambda *args, **kwargs: MagicMock(name="ChatOpenAI"),
    )

    # Clear the module-level model cache between tests so cached instances from
    # one test don't leak into another.
    from autored import router
    router._model_cache.clear()

    yield

    router._model_cache.clear()
