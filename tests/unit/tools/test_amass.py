"""Tests for the amass tool wrapper (Phase 1, Task 13).

The fixture file is ``amass_lame.json`` (``.json`` extension) but the
content is JSONL — one JSON object per line — matching what the real
amass binary emits with ``-json -``.
"""
import pytest

from autored.config import load_roe
from autored.roe_guard import register_roe
from autored.subprocess_runner import SubprocessResult
from autored.tools.amass import (
    _build_amass_cmd,
    _parse_amass_jsonl,
    amass_enum,
)
from autored.tools.subfinder import SubdomainList


def test_parse_amass_jsonl(fixtures_dir):
    text = (fixtures_dir / "amass_lame.json").read_text()
    result = _parse_amass_jsonl(text, "lame.htb")
    assert isinstance(result, SubdomainList)
    assert result.domain == "lame.htb"
    assert "lame.htb" in result.subdomains
    assert "mail.lame.htb" in result.subdomains


def test_parse_amass_empty():
    result = _parse_amass_jsonl("", "example.com")
    assert result.subdomains == []


def test_build_amass_cmd():
    cmd = _build_amass_cmd("lame.htb")
    assert "amass" in cmd[0]
    assert "enum" in cmd
    assert "-passive" in cmd
    assert "-d" in cmd
    assert "lame.htb" in cmd


@pytest.mark.asyncio
async def test_amass_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, fixtures_dir, monkeypatch
):
    """Integration test: call the decorated tool end-to-end via .ainvoke().

    Regression catcher for the decorator-stacking bug (C1+C2 from Batch A
    review): the brief's spec'd ``@roe_guard`` over ``@tool`` order produced
    a StructuredTool that was not callable via ``.ainvoke({...})``. With the
    swapped order (``@tool`` outermost, ``@roe_guard`` inner), the
    StructuredTool's underlying coroutine is a regular async def, and
    ``.ainvoke({...})`` dispatches correctly through the RoE wrapper.

    Note: ``_save_raw`` is imported into ``amass``'s namespace via
    ``from autored.tools.nmap import _save_raw``, so the patch target must
    be ``autored.tools.amass._save_raw`` (not ``autored.tools.nmap._save_raw``)
    to intercept the call from inside ``amass_enum``.
    """
    # 1. Register a RoE for the test engagement.
    roe = load_roe(sandbox_roe_yaml)
    register_roe("amass-int", roe)

    # 2. Mock run_subprocess to return the fixture JSONL as stdout.
    amass_jsonl = (fixtures_dir / "amass_lame.json").read_text()

    async def fake_run_subprocess(cmd, timeout=600):
        return SubprocessResult(
            stdout=amass_jsonl,
            stderr="",
            returncode=0,
            duration_sec=0.3,
            command=" ".join(cmd),
        )

    monkeypatch.setattr("autored.tools.amass.run_subprocess", fake_run_subprocess)

    # 3. Mock _save_raw to a no-op so the test doesn't touch disk. The patch
    #    target is amass's namespace because ``from x import y`` copies the
    #    reference at import time — patching the source module's attribute
    #    wouldn't affect the local binding.
    async def fake_save_raw(*args, **kwargs):
        return ""

    monkeypatch.setattr("autored.tools.amass._save_raw", fake_save_raw)

    # 4. Call the tool via .ainvoke({...}).
    result = await amass_enum.ainvoke(
        {
            "domain": "lame.htb",
            "engagement_id": "amass-int",
        }
    )

    # 5. Assert the returned object is the right Pydantic model with the
    #    expected fields populated.
    assert isinstance(result, SubdomainList)
    assert result.domain == "lame.htb"
    assert "lame.htb" in result.subdomains
    assert "mail.lame.htb" in result.subdomains
    assert "dnsdb" in result.sources
    assert "hackertarget" in result.sources
