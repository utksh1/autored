from __future__ import annotations

import pytest

from autored.subprocess_runner import run_subprocess, SubprocessResult


@pytest.mark.asyncio
async def test_run_subprocess_success():
    result = await run_subprocess(["echo", "hello"], timeout=5)
    assert result.returncode == 0
    assert "hello" in result.stdout
    assert result.duration_sec >= 0


@pytest.mark.asyncio
async def test_run_subprocess_nonzero_exit():
    result = await run_subprocess(["false"], timeout=5)
    assert result.returncode != 0


@pytest.mark.asyncio
async def test_run_subprocess_timeout():
    with pytest.raises(TimeoutError) as exc:
        await run_subprocess(["sleep", "10"], timeout=1)
    assert "timed out" in str(exc.value).lower() or "timeout" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_run_subprocess_captures_stderr():
    result = await run_subprocess(["sh", "-c", "echo bad >&2; exit 1"], timeout=5)
    assert result.returncode == 1
    assert "bad" in result.stderr


def test_subprocess_result_model():
    r = SubprocessResult(
        stdout="out", stderr="err", returncode=0,
        duration_sec=1.5, command="echo hello",
    )
    assert r.stdout == "out"
    assert r.returncode == 0
