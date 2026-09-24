"""Tests for the subfinder tool wrapper (Phase 1, Task 12).

The fixture file is ``subfinder_lame.json`` (``.json`` extension) but the
content is JSONL — one JSON object per line — matching what the real
subfinder binary emits with ``-json``.
"""
import pytest

from autored.config import load_roe
from autored.roe_guard import register_roe
from autored.subprocess_runner import SubprocessResult
from autored.tools.subfinder import (
    SubdomainList,
    _build_subfinder_cmd,
    _parse_subfinder_jsonl,
    subfinder_enum,
)


def test_parse_subfinder_jsonl(fixtures_dir):
    text = (fixtures_dir / "subfinder_lame.json").read_text()
    result = _parse_subfinder_jsonl(text, "lame.htb")
    assert isinstance(result, SubdomainList)
    assert result.domain == "lame.htb"
    assert "www.lame.htb" in result.subdomains
    assert "ftp.lame.htb" in result.subdomains


def test_parse_subfinder_empty():
    result = _parse_subfinder_jsonl("", "example.com")
    assert result.subdomains == []


def test_build_subfinder_cmd():
    cmd = _build_subfinder_cmd("lame.htb")
    assert "subfinder" in cmd[0]
    assert "-d" in cmd
    assert "lame.htb" in cmd
    assert "-json" in cmd


@pytest.mark.asyncio
async def test_subfinder_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, fixtures_dir, monkeypatch
):
    """Integration test: call the decorated tool end-to-end via .ainvoke().

    Regression catcher for the decorator-stacking bug (C1+C2 from Batch A
    review): the brief's spec'd ``@roe_guard`` over ``@tool`` order produced
    a StructuredTool that was not callable via ``.ainvoke({...})``
    (``TypeError: 'StructuredTool' object is not callable``). With the
    swapped order (``@tool`` outermost, ``@roe_guard`` inner), the
    StructuredTool's underlying coroutine is a regular async def, and
    ``.ainvoke({...})`` dispatches correctly through the RoE wrapper.

    Note: ``_save_raw`` is imported into ``subfinder``'s namespace via
    ``from autored.tools.nmap import _save_raw``, so the patch target must
    be ``autored.tools.subfinder._save_raw`` to intercept the call from
    inside ``subfinder_enum``.
    """
    # 1. Register a RoE for the test engagement.
    roe = load_roe(sandbox_roe_yaml)
    register_roe("subfinder-int", roe)

    # 2. Mock run_subprocess to return the fixture JSONL as stdout.
    subfinder_json = (fixtures_dir / "subfinder_lame.json").read_text()

    async def fake_run_subprocess(cmd, timeout=120):
        return SubprocessResult(
            stdout=subfinder_json,
            stderr="",
            returncode=0,
            duration_sec=0.3,
            command=" ".join(cmd),
        )

    monkeypatch.setattr("autored.tools.subfinder.run_subprocess", fake_run_subprocess)

    # 3. Mock _save_raw to a no-op so the test doesn't touch disk.
    async def fake_save_raw(*args, **kwargs):
        return ""

    monkeypatch.setattr("autored.tools.subfinder._save_raw", fake_save_raw)

    # 4. Call the tool via .ainvoke({...}).
    result = await subfinder_enum.ainvoke(
        {
            "domain": "lame.htb",
            "engagement_id": "subfinder-int",
        }
    )

    # 5. Assert the returned object is the right Pydantic model with the
    #    expected fields populated.
    assert isinstance(result, SubdomainList)
    assert result.domain == "lame.htb"
    assert "www.lame.htb" in result.subdomains
    assert "ftp.lame.htb" in result.subdomains
    assert "crtsh" in result.sources
