from __future__ import annotations

import pytest

from autored.retry import with_retry


@pytest.mark.asyncio
async def test_retry_succeeds_first_try():
    call_count = 0

    @with_retry(max_attempts=3, base_delay=0.01)
    async def quick():
        nonlocal call_count
        call_count += 1
        return "ok"

    result = await quick()
    assert result == "ok"
    assert call_count == 1


@pytest.mark.asyncio
async def test_retry_succeeds_after_failure():
    call_count = 0

    @with_retry(max_attempts=3, base_delay=0.01)
    async def flaky():
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise RuntimeError("transient")
        return "recovered"

    result = await flaky()
    assert result == "recovered"
    assert call_count == 2


@pytest.mark.asyncio
async def test_retry_exhausts_attempts():
    call_count = 0

    @with_retry(max_attempts=3, base_delay=0.01)
    async def always_fails():
        nonlocal call_count
        call_count += 1
        raise RuntimeError("permanent")

    with pytest.raises(RuntimeError, match="permanent"):
        await always_fails()
    assert call_count == 3
