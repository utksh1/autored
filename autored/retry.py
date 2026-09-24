"""AutoRed retry decorator — exponential backoff with jitter."""
from __future__ import annotations

import asyncio
import functools
import random

from autored.logging import get_logger

log = get_logger("retry")


def with_retry(max_attempts: int = 3, base_delay: float = 1.0):
    """Decorator factory. Retries an async function with exponential backoff."""

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            last_exc: Exception | None = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return await func(*args, **kwargs)
                except Exception as exc:
                    last_exc = exc
                    if attempt >= max_attempts:
                        log.error(
                            "retry_exhausted",
                            function=func.__name__,
                            attempts=attempt,
                            error=str(exc),
                        )
                        raise
                    delay = base_delay * (2 ** (attempt - 1)) + random.uniform(0, 0.1)
                    log.warning(
                        "retry_attempt",
                        function=func.__name__,
                        attempt=attempt,
                        delay=delay,
                        error=str(exc),
                    )
                    await asyncio.sleep(delay)
            # unreachable
            raise last_exc  # type: ignore[misc]

        return wrapper

    return decorator
