# tests/unit/test_retry.py
import pytest

from autored.retry import with_retry

@pytest.mark.asyncio
async def test_retry_succeeds_first_try():
    call_count = 0

    @with_retry(max_attempts=3, base_delay=0.01)
    async def succeeds():
        nonlocal call_count
        call_count += 1
        return "ok"

    result = await succeeds()
    assert result == "ok"
    assert call_count == 1

@pytest.mark.asyncio
async def test_retry_succeeds_after_failure():
    call_count = 0

    @with_retry(max_attempts=3, base_delay=0.01)
    async def fails_then_succeeds():
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise ValueError("fail")
        return "ok"

    result = await fails_then_succeeds()
    assert result == "ok"
    assert call_count == 2

@pytest.mark.asyncio
async def test_retry_exhausts_attempts():
    call_count = 0

    @with_retry(max_attempts=3, base_delay=0.01)
    async def always_fails():
        nonlocal call_count
        call_count += 1
        raise ValueError("always")

    with pytest.raises(ValueError):
        await always_fails()
    assert call_count == 3
