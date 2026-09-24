"""Tests for the secretsdump tool wrapper (Phase 4, Task 5).

Same Phase 4 stub pattern as the T3 linpeas / winpeas wrappers and the
sibling mimikatz wrapper — ``_parse_secretsdump_output`` is exercised
directly via a fixture file, and the ``secretsdump`` ``@tool`` is
exercised end-to-end via ``.ainvoke({...})`` with ``_save_raw`` mocked.
Per the T5 brief, ``secretsdump`` constructs the impacket-secretsdump
command string and saves it; real execution is deferred to the Phase 6
FootholdSessionManager.
"""
from __future__ import annotations

import pytest

from autored.config import load_roe
from autored.roe_guard import register_roe
from autored.tools.secretsdump import (
    SecretsdumpResult,
    _parse_secretsdump_output,
    secretsdump,
)


def test_parse_secretsdump_output(fixtures_dir):
    """Parser pulls the SAM-hash lines (``username:rid:lmhash:nthash:::``)
    out of a representative impacket-secretsdump stdout fixture."""
    text = (fixtures_dir / "secretsdump_output.txt").read_text()
    result = _parse_secretsdump_output(text, "10.10.10.5")
    assert isinstance(result, SecretsdumpResult)
    # Should find Administrator + Guest (>= 2 hashes)
    assert len(result.hashes) >= 2
    assert any(h["username"] == "Administrator" for h in result.hashes)
    assert any(h["username"] == "Guest" for h in result.hashes)
    # Should find the NTLM hash
    assert any(
        "31d6cfe0d16ae931b73c59d7e0c089c0" in h["nthash"] for h in result.hashes
    )
    # RIDs should be parsed
    admin = next(h for h in result.hashes if h["username"] == "Administrator")
    assert admin["rid"] == "500"


def test_parse_secretsdump_empty():
    """Empty stdout must not crash the parser and must yield an empty list."""
    result = _parse_secretsdump_output("", "10.10.10.5")
    assert isinstance(result, SecretsdumpResult)
    assert result.hashes == []
    assert result.host_ip == "10.10.10.5"


@pytest.mark.asyncio
async def test_secretsdump_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, monkeypatch
):
    """Integration test: call the decorated tool end-to-end via .ainvoke().

    Same regression-catcher rationale as the sibling mimikatz integration
    test — ``@tool`` outermost + ``@roe_guard`` inner per Ruling 1.
    """
    roe = load_roe(sandbox_roe_yaml)
    register_roe("secretsdump-int", roe)

    async def fake_save_raw(*args, **kwargs):
        return "/tmp/fake/secretsdump_cmd.out"

    monkeypatch.setattr("autored.tools.secretsdump._save_raw", fake_save_raw)

    result = await secretsdump.ainvoke(
        {
            "target": "10.10.10.5",
            "username": "Administrator",
            "password": "P@ssw0rd!",
            "nthash": "",
            "engagement_id": "secretsdump-int",
        }
    )

    assert isinstance(result, SecretsdumpResult)
    assert result.host_ip == "10.10.10.5"
    # Phase 4 stub: raw_output_path is set (command was saved) but the
    # hashes list is empty because the tool did not actually execute.
    assert result.raw_output_path == "/tmp/fake/secretsdump_cmd.out"
    assert result.hashes == []
