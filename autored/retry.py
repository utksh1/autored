import asyncio
from functools import wraps
from autored.logging import get_logger

log = get_logger("retry")

def with_retry(max_attempts: int = 3, base_delay: float = 2.0):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_attempts):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt == max_attempts - 1:
                        log.error("retry_exhausted", func=func.__name__,
                                  attempts=max_attempts, error=str(e))
                        raise
                    delay = base_delay * (2 ** attempt)
                    log.warning("retry_attempt", func=func.__name__,
                                attempt=attempt + 1, max=max_attempts,
                                error=str(e), retry_in=delay)
                    await asyncio.sleep(delay)
            raise last_exception  # unreachable
        return wrapper
    return decorator
