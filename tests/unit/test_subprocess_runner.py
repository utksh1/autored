# tests/unit/test_subprocess_runner.py
import pytest

from autored.subprocess_runner import run_subprocess

@pytest.mark.asyncio
async def test_run_subprocess_success():
    result = await run_subprocess(["echo", "hello"], timeout=5)
    assert result.returncode == 0
    assert "hello" in result.stdout
    assert result.stderr == ""
    assert result.duration_sec >= 0

@pytest.mark.asyncio
async def test_run_subprocess_nonzero_exit():
    result = await run_subprocess(["false"], timeout=5)
    assert result.returncode != 0

@pytest.mark.asyncio
async def test_run_subprocess_timeout():
    with pytest.raises(TimeoutError) as exc:
        await run_subprocess(["sleep", "10"], timeout=1)
    assert "timed out" in str(exc.value).lower()

@pytest.mark.asyncio
async def test_run_subprocess_captures_stderr():
    result = await run_subprocess(["sh", "-c", "echo err >&2"], timeout=5)
    assert "err" in result.stderr
