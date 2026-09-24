"""Tests for the feroxbuster tool wrapper (Phase 1, Task 11).

The fixture file is ``feroxbuster_lame.json`` (``.json`` extension) but the
content is JSONL — one JSON object per line — matching what the real
feroxbuster binary emits with ``--json``.
"""
import pytest

from autored.config import load_roe
from autored.roe_guard import register_roe
from autored.subprocess_runner import SubprocessResult
from autored.tools.feroxbuster import (
    DirResult,
    FeroxbusterOutput,
    _build_feroxbuster_cmd,
    _parse_feroxbuster_jsonl,
    feroxbuster_dir,
)


def test_parse_feroxbuster_jsonl(fixtures_dir):
    text = (fixtures_dir / "feroxbuster_lame.json").read_text()
    results = _parse_feroxbuster_jsonl(text)
    assert len(results) == 2
    assert results[0].url == "http://10.10.10.5/icons/"
    assert results[0].status_code == 403
    assert results[1].url == "http://10.10.10.5/index.html"
    assert results[1].extension == "html"


def test_parse_feroxbuster_empty():
    assert _parse_feroxbuster_jsonl("") == []


def test_build_feroxbuster_cmd():
    cmd = _build_feroxbuster_cmd(
        "http://10.10.10.5", "/usr/share/wordlists/dirb/common.txt", 3
    )
    assert "feroxbuster" in cmd[0]
    assert "-u" in cmd
    assert "http://10.10.10.5" in cmd
    assert "-w" in cmd
    assert "/usr/share/wordlists/dirb/common.txt" in cmd
    assert "-d" in cmd
    assert "3" in cmd
    assert "--json" in cmd


@pytest.mark.asyncio
async def test_feroxbuster_ainvoke_works_with_roe_guard(
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

    Note: ``_save_raw`` is imported into ``feroxbuster``'s namespace via
    ``from autored.tools.nmap import _save_raw``, so the patch target must
    be ``autored.tools.feroxbuster._save_raw`` to intercept the call from
    inside ``feroxbuster_dir``.
    """
    # 1. Register a RoE for the test engagement.
    roe = load_roe(sandbox_roe_yaml)
    register_roe("feroxbuster-int", roe)

    # 2. Mock run_subprocess to return the fixture JSONL as stdout.
    feroxbuster_json = (fixtures_dir / "feroxbuster_lame.json").read_text()

    async def fake_run_subprocess(cmd, timeout=600):
        return SubprocessResult(
            stdout=feroxbuster_json,
            stderr="",
            returncode=0,
            duration_sec=0.5,
            command=" ".join(cmd),
        )

    monkeypatch.setattr(
        "autored.tools.feroxbuster.run_subprocess", fake_run_subprocess
    )

    # 3. Mock _save_raw to a no-op so the test doesn't touch disk.
    async def fake_save_raw(*args, **kwargs):
        return ""

    monkeypatch.setattr("autored.tools.feroxbuster._save_raw", fake_save_raw)

    # 4. Call the tool via .ainvoke({...}).
    result = await feroxbuster_dir.ainvoke(
        {
            "url": "http://10.10.10.5",
            "wordlist": "/usr/share/wordlists/dirb/common.txt",
            "depth": 3,
            "engagement_id": "feroxbuster-int",
        }
    )

    # 5. Assert the returned object is the right Pydantic model with the
    #    expected fields populated.
    assert isinstance(result, FeroxbusterOutput)
    assert result.target_url == "http://10.10.10.5"
    assert len(result.results) == 2
    assert isinstance(result.results[0], DirResult)
    assert result.results[0].url == "http://10.10.10.5/icons/"
    assert result.results[0].status_code == 403
    assert result.results[1].url == "http://10.10.10.5/index.html"
    assert result.results[1].extension == "html"
