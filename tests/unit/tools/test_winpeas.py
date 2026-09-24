"""Tests for the winpeas tool wrapper (Phase 4, Task 3).

Same pattern as ``test_linpeas.py`` — ``_parse_winpeas_output`` exercised
directly via a fixture file, ``winpeas_run`` exercised end-to-end via
``.ainvoke({...})`` with ``_save_raw`` mocked. Per the T3 brief, ``winpeas_run``
constructs the winpeas command string and saves it; real execution is deferred
to the Phase 6 FootholdSessionManager.
"""
from __future__ import annotations

import pytest

from autored.config import load_roe
from autored.roe_guard import register_roe
from autored.tools.winpeas import WinpeasResult, _parse_winpeas_output, winpeas_run


def test_parse_winpeas_output(fixtures_dir):
    """Parser pulls autologon creds, modifiable services, and unattended files
    out of a representative winpeas stdout fixture."""
    text = (fixtures_dir / "winpeas_output.txt").read_text()
    result = _parse_winpeas_output(text, "10.10.10.5")
    assert isinstance(result, WinpeasResult)
    # Should find autologon creds
    assert len(result.autologon_credentials) >= 1
    cred = result.autologon_credentials[0]
    assert cred["username"] == "Administrator"
    assert cred["password"] == "P@ssw0rd123!"
    assert cred["domain"] == "CORP"
    # Should find modifiable services
    assert len(result.modifiable_services) >= 1
    # Should find unattended files
    assert len(result.unattended_files) >= 1
    assert any("Unattend.xml" in f for f in result.unattended_files)


def test_parse_winpeas_empty():
    """Empty stdout must not crash the parser and must yield empty lists."""
    result = _parse_winpeas_output("", "10.10.10.5")
    assert isinstance(result, WinpeasResult)
    assert result.autologon_credentials == []
    assert result.modifiable_services == []
    assert result.unattended_files == []
    assert result.host_ip == "10.10.10.5"


@pytest.mark.asyncio
async def test_winpeas_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, monkeypatch
):
    """Integration test: call the decorated tool end-to-end via .ainvoke().

    Same regression-catcher rationale as ``test_linpeas_ainvoke_works_with_roe_guard``
    — ``@tool`` outermost + ``@roe_guard`` inner per Ruling 1.
    """
    roe = load_roe(sandbox_roe_yaml)
    register_roe("winpeas-int", roe)

    async def fake_save_raw(*args, **kwargs):
        return "/tmp/fake/winpeas_cmd.out"

    monkeypatch.setattr("autored.tools.winpeas._save_raw", fake_save_raw)

    result = await winpeas_run.ainvoke(
        {
            "foothold_id": "fh-001",
            "host_ip": "10.10.10.5",
            "engagement_id": "winpeas-int",
        }
    )

    assert isinstance(result, WinpeasResult)
    assert result.host_ip == "10.10.10.5"
    assert result.raw_output_path == "/tmp/fake/winpeas_cmd.out"
    # Phase 4 stub: parse lists are empty because the tool did not execute.
    assert result.autologon_credentials == []
    assert result.modifiable_services == []
    assert result.unattended_files == []
