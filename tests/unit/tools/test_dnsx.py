"""Tests for the dnsx tool wrapper (Phase 1, Task 14).

The fixture file is ``dnsx_lame.json`` (``.json`` extension) but the
content is JSONL — one JSON object per line — matching what the real
dnsx binary emits with ``-json``.
"""
import pytest

from autored.config import load_roe
from autored.roe_guard import register_roe
from autored.subprocess_runner import SubprocessResult
from autored.tools.dnsx import (
    DnsOutput,
    DnsRecord,
    DnsResult,
    _build_dnsx_cmd,
    _parse_dnsx_jsonl,
    dns_resolve,
)


def test_parse_dnsx_jsonl(fixtures_dir):
    text = (fixtures_dir / "dnsx_lame.json").read_text()
    results = _parse_dnsx_jsonl(text)
    assert len(results) == 2
    assert results[0].hostname == "lame.htb"
    assert any(
        r.record_type == "A" and r.value == "10.10.10.5" for r in results[0].records
    )
    assert results[1].hostname == "www.lame.htb"
    assert any(r.record_type == "CNAME" for r in results[1].records)


def test_parse_dnsx_empty():
    assert _parse_dnsx_jsonl("") == []


def test_build_dnsx_cmd():
    cmd = _build_dnsx_cmd(["lame.htb", "www.lame.htb"])
    assert "dnsx" in cmd[0]
    assert "-d" in cmd or "-l" in cmd
    assert "-a" in cmd
    assert "-aaaa" in cmd
    assert "-json" in cmd


@pytest.mark.asyncio
async def test_dnsx_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, fixtures_dir, monkeypatch
):
    """Integration test: call the decorated tool end-to-end via .ainvoke().

    Regression catcher for the decorator-stacking bug (C1+C2 from Batch A
    review): the brief's spec'd ``@roe_guard`` over ``@tool`` order produced
    a StructuredTool that was not callable via ``.ainvoke({...})``. With the
    swapped order (``@tool`` outermost, ``@roe_guard`` inner), the
    StructuredTool's underlying coroutine is a regular async def, and
    ``.ainvoke({...})`` dispatches correctly through the RoE wrapper.

    Note: ``_save_raw`` is imported into ``dnsx``'s namespace via
    ``from autored.tools.nmap import _save_raw``, so the patch target must
    be ``autored.tools.dnsx._save_raw`` (not ``autored.tools.nmap._save_raw``)
    to intercept the call from inside ``dns_resolve``.
    """
    # 1. Register a RoE for the test engagement.
    roe = load_roe(sandbox_roe_yaml)
    register_roe("dnsx-int", roe)

    # 2. Mock run_subprocess to return the fixture JSONL as stdout.
    dnsx_jsonl = (fixtures_dir / "dnsx_lame.json").read_text()

    async def fake_run_subprocess(cmd, timeout=60):
        return SubprocessResult(
            stdout=dnsx_jsonl,
            stderr="",
            returncode=0,
            duration_sec=0.3,
            command=" ".join(cmd),
        )

    monkeypatch.setattr("autored.tools.dnsx.run_subprocess", fake_run_subprocess)

    # 3. Mock _save_raw to a no-op so the test doesn't touch disk. The patch
    #    target is dnsx's namespace because ``from x import y`` copies the
    #    reference at import time — patching the source module's attribute
    #    wouldn't affect the local binding.
    async def fake_save_raw(*args, **kwargs):
        return ""

    monkeypatch.setattr("autored.tools.dnsx._save_raw", fake_save_raw)

    # 4. Call the tool via .ainvoke({...}).
    result = await dns_resolve.ainvoke(
        {
            "hostnames": ["lame.htb", "www.lame.htb"],
            "engagement_id": "dnsx-int",
        }
    )

    # 5. Assert the returned object is the right Pydantic model with the
    #    expected fields populated.
    assert isinstance(result, DnsOutput)
    assert len(result.results) == 2
    assert isinstance(result.results[0], DnsResult)
    assert result.results[0].hostname == "lame.htb"
    assert any(
        isinstance(r, DnsRecord)
        and r.record_type == "A"
        and r.value == "10.10.10.5"
        for r in result.results[0].records
    )
    assert result.results[1].hostname == "www.lame.htb"
    assert any(r.record_type == "CNAME" for r in result.results[1].records)
