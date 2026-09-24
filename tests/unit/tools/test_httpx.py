"""Tests for the httpx tool wrapper (Phase 1, Task 9).

File is named ``httpx_tool.py`` (not ``httpx.py``) to avoid clobbering the
real ``httpx`` Python package on the import path.
"""
import pytest

from autored.config import load_roe
from autored.roe_guard import register_roe
from autored.subprocess_runner import SubprocessResult
from autored.tools.httpx_tool import (
    HttpxOutput,
    HttpxResult,
    _build_httpx_cmd,
    _parse_httpx_json,
    httpx_probe,
)


def test_parse_httpx_json(fixtures_dir):
    text = (fixtures_dir / "httpx_lame.json").read_text()
    results = _parse_httpx_json(text)
    assert len(results) == 1
    r = results[0]
    assert r.url == "http://10.10.10.5"
    assert r.status_code == 301
    assert "Apache" in r.tech_stack
    assert r.web_server == "Apache/2.2.8 (Ubuntu) DAV/2"
    assert r.redirects is True
    assert r.final_url == "https://10.10.10.5/"


def test_parse_httpx_empty():
    assert _parse_httpx_json("") == []


def test_build_httpx_cmd():
    cmd = _build_httpx_cmd(["10.10.10.5"], [80, 443])
    assert "httpx" in cmd[0]
    assert "-u" in cmd or "-l" in cmd  # accepts single or list
    assert "-tech-detect" in cmd
    assert "-status-code" in cmd
    assert "-json" in cmd


def test_httpx_output_empty_result():
    """Calling httpx_probe with no hosts returns an empty HttpxOutput
    without invoking the subprocess. Sanity-check the empty contract.
    """
    out = HttpxOutput()
    assert out.results == []
    assert out.raw_output_path == ""
    assert out.command == ""
    assert out.duration_sec == 0.0
    # And HttpxResult has the documented fields with sensible defaults.
    r = HttpxResult(url="http://x", status_code=200)
    assert r.tech_stack == []
    assert r.content_length == 0
    assert r.redirects is False


@pytest.mark.asyncio
async def test_httpx_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, fixtures_dir, monkeypatch
):
    """Integration test: call the decorated tool end-to-end via .ainvoke().

    Regression catcher for the decorator-stacking bug (C1+C2): the old
    ``@roe_guard`` over ``@tool`` order produced a StructuredTool that was
    not callable via ``.ainvoke({...})``. With the swapped order
    (``@tool`` outermost, ``@roe_guard`` inner), the StructuredTool's
    underlying coroutine is a regular async def, and ``.ainvoke({...})``
    dispatches correctly through the RoE wrapper.

    Note: ``_save_raw`` is imported into ``httpx_tool``'s namespace via
    ``from autored.tools.nmap import _save_raw``, so the patch target must
    be ``autored.tools.httpx_tool._save_raw`` (not
    ``autored.tools.nmap._save_raw``) to intercept the call from inside
    ``httpx_probe``.
    """
    # 1. Register a RoE for the test engagement.
    roe = load_roe(sandbox_roe_yaml)
    register_roe("httpx-int", roe)

    # 2. Mock run_subprocess to return the fixture JSONL as stdout.
    httpx_json = (fixtures_dir / "httpx_lame.json").read_text()

    async def fake_run_subprocess(cmd, timeout=120):
        return SubprocessResult(
            stdout=httpx_json,
            stderr="",
            returncode=0,
            duration_sec=0.2,
            command=" ".join(cmd),
        )

    monkeypatch.setattr(
        "autored.tools.httpx_tool.run_subprocess", fake_run_subprocess
    )

    # 3. Mock _save_raw to a no-op so the test doesn't touch disk.
    async def fake_save_raw(*args, **kwargs):
        return ""

    monkeypatch.setattr("autored.tools.httpx_tool._save_raw", fake_save_raw)

    # 4. Call the tool via .ainvoke({...}).
    result = await httpx_probe.ainvoke(
        {
            "hosts": ["10.10.10.5"],
            "ports": [80, 443],
            "engagement_id": "httpx-int",
        }
    )

    # 5. Assert the returned object is the right Pydantic model with the
    #    expected fields populated.
    assert isinstance(result, HttpxOutput)
    assert len(result.results) == 1
    r = result.results[0]
    assert isinstance(r, HttpxResult)
    assert r.url == "http://10.10.10.5"
    assert r.status_code == 301
    assert "Apache" in r.tech_stack
    assert r.web_server == "Apache/2.2.8 (Ubuntu) DAV/2"
    assert r.redirects is True
    assert r.final_url == "https://10.10.10.5/"
