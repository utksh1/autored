"""Tests for the linpeas tool wrapper (Phase 4, Task 3).

Pattern mirrors the Phase 1/3 tool wrappers — ``_parse_linpeas_output`` is
exercised directly via a fixture file (so the regex extraction has a stable,
reviewable contract), and the ``linpeas_run`` ``@tool`` is exercised end-to-end
via ``.ainvoke({...})`` with ``_save_raw`` mocked so the test never touches disk
(same as the Batch A integration-test pattern in ``test_nmap.py`` and
``test_hydra.py``).
"""
from __future__ import annotations

import pytest

from autored.config import load_roe
from autored.roe_guard import register_roe
from autored.tools.linpeas import LinpeasResult, _parse_linpeas_output, linpeas_run


def test_parse_linpeas_output(fixtures_dir):
    """Parser pulls CVEs, SUID binaries, cron jobs, and sudo entries out of
    a representative linpeas stdout fixture."""
    text = (fixtures_dir / "linpeas_output.txt").read_text()
    result = _parse_linpeas_output(text, "10.10.10.5")
    assert isinstance(result, LinpeasResult)
    # Should find SUID entries (paths containing "/")
    assert len(result.suid_binaries) >= 1
    assert any("/usr/bin" in b for b in result.suid_binaries)
    # Should find CVEs
    assert any("CVE" in c for c in result.cves)
    assert "CVE-2022-0847" in result.cves
    assert "CVE-2021-4034" in result.cves
    # Should find cron jobs
    assert len(result.cron_jobs) >= 1
    assert any("backup.py" in c for c in result.cron_jobs)
    # Should find sudo entries
    assert len(result.sudo_entries) >= 1


def test_parse_linpeas_empty():
    """Empty stdout must not crash the parser and must yield empty lists."""
    result = _parse_linpeas_output("", "10.10.10.5")
    assert isinstance(result, LinpeasResult)
    assert result.suid_binaries == []
    assert result.cves == []
    assert result.cron_jobs == []
    assert result.sudo_entries == []
    assert result.host_ip == "10.10.10.5"


@pytest.mark.asyncio
async def test_linpeas_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, monkeypatch
):
    """Integration test: call the decorated tool end-to-end via .ainvoke().

    Regression catcher for the decorator-stacking bug (Ruling 1 in the SDD
    ledger): ``@tool`` must be applied OUTERMOST and ``@roe_guard`` INNER,
    or the resulting StructuredTool is not callable via ``.ainvoke({...})``.

    Per the T3 brief, ``linpeas_run`` does NOT actually execute subprocess —
    it constructs the linpeas curl-pipe-sh command string and persists it via
    ``_save_raw`` so the Phase 6 FootholdSessionManager can replay the command
    against the foothold's shell session. So we mock ``_save_raw`` only — no
    ``run_subprocess`` mock needed for this tool.
    """
    roe = load_roe(sandbox_roe_yaml)
    register_roe("linpeas-int", roe)

    async def fake_save_raw(*args, **kwargs):
        return "/tmp/fake/linpeas_cmd.out"

    monkeypatch.setattr("autored.tools.linpeas._save_raw", fake_save_raw)

    result = await linpeas_run.ainvoke(
        {
            "foothold_id": "fh-001",
            "host_ip": "10.10.10.5",
            "engagement_id": "linpeas-int",
        }
    )

    assert isinstance(result, LinpeasResult)
    assert result.host_ip == "10.10.10.5"
    # Phase 4 stub: raw_output_path is set (command was saved) but the
    # parse lists are empty because the tool did not actually execute.
    assert result.raw_output_path == "/tmp/fake/linpeas_cmd.out"
    assert result.suid_binaries == []
    assert result.cves == []
    assert result.cron_jobs == []
