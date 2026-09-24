"""Tests for the bloodhound tool wrapper (Phase 4, Task 4).

Pattern mirrors the Phase 1/3 tool wrappers — ``_build_bloodhound_cmd`` is
exercised directly (so the CLI argv contract has a stable, reviewable
surface) and the ``bloodhound_collect`` ``@tool`` is exercised end-to-end
via ``.ainvoke({...})`` with ``run_subprocess`` and ``_save_raw`` mocked
so the test never touches the network or disk.

Unlike the T3 linpeas/winpeas wrappers, ``bloodhound_collect`` DOES
execute ``run_subprocess`` in Phase 4 — it is the only Phase 4 tool that
actually shells out. The brief specifies that no in-memory parsing of the
BloodHound JSON output happens here; the stdout is saved to disk via
``_save_raw`` and Phase 5 (Neo4j upload + Cypher query) owns downstream
processing.
"""
from __future__ import annotations

import pytest

from autored.config import load_roe
from autored.roe_guard import register_roe
from autored.subprocess_runner import SubprocessResult
from autored.tools.bloodhound import (
    BloodhoundResult,
    _build_bloodhound_cmd,
    bloodhound_collect,
)


def test_build_bloodhound_cmd():
    """Built argv contains all the brief-mandated flags + values in the
    canonical bloodhound-python order."""
    cmd = _build_bloodhound_cmd("user", "pass", "CORP.LOCAL", "10.10.10.5")
    assert "bloodhound-python" in cmd[0]
    assert "-u" in cmd
    assert "user" in cmd
    assert "-p" in cmd
    assert "pass" in cmd
    assert "-d" in cmd
    assert "CORP.LOCAL" in cmd
    assert "-ns" in cmd
    assert "-c" in cmd
    assert "All" in cmd
    assert "10.10.10.5" in cmd


def test_bloodhound_result_model():
    """The result model accepts the brief-specified fields + defaults."""
    r = BloodhoundResult(
        domain="CORP.LOCAL",
        host="10.10.10.5",
        json_output_path="/tmp/bloodhound_data",
        computers=[],
        users=[],
        sessions=[],
    )
    assert r.domain == "CORP.LOCAL"
    assert r.host == "10.10.10.5"
    assert r.json_output_path == "/tmp/bloodhound_data"
    assert r.computers == []
    assert r.users == []
    assert r.sessions == []
    assert r.raw_output_path == ""
    assert r.duration_sec == 0.0


@pytest.mark.asyncio
async def test_bloodhound_collect_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, monkeypatch
):
    """Integration test: call the decorated tool end-to-end via .ainvoke().

    Regression catcher for the decorator-stacking bug (Ruling 1 in the SDD
    ledger): ``@tool`` must be applied OUTERMOST and ``@roe_guard`` INNER,
    or the resulting StructuredTool is not callable via ``.ainvoke({...})``.

    Unlike T3's linpeas/winpeas (which only mock ``_save_raw`` because they
    do not execute subprocess), this test must mock BOTH ``run_subprocess``
    and ``_save_raw`` — bloodhound_collect is the one Phase 4 tool that
    actually shells out, so the SubprocessResult shape it consumes must be
    realistic (returncode + stdout + stderr + duration_sec + command).
    """
    roe = load_roe(sandbox_roe_yaml)
    register_roe("bh-int", roe)

    # bloodhound-python stdout is the standard collection log — a few INFO
    # lines followed by the JSON dump file names. We don't parse it in
    # Phase 4 (per brief), so a small fixture-like blob is enough.
    fake_stdout = (
        "INFO: Connected to CORP.LOCAL\n"
        "INFO: Found 4 computers\n"
        "INFO: Found 12 users\n"
        "INFO: Compressing output to computers.json / users.json / sessions.json\n"
    )

    async def fake_run_subprocess(cmd, timeout=600):
        return SubprocessResult(
            stdout=fake_stdout,
            stderr="",
            returncode=0,
            duration_sec=12.5,
            command=" ".join(cmd),
        )

    monkeypatch.setattr(
        "autored.tools.bloodhound.run_subprocess", fake_run_subprocess
    )

    async def fake_save_raw(*args, **kwargs):
        return "/tmp/fake/bloodhound.out"

    monkeypatch.setattr("autored.tools.bloodhound._save_raw", fake_save_raw)

    result = await bloodhound_collect.ainvoke(
        {
            "username": "svc_scan",
            "password": "P@ssw0rd!",
            "domain": "CORP.LOCAL",
            "host": "10.10.10.5",
            "engagement_id": "bh-int",
        }
    )

    assert isinstance(result, BloodhoundResult)
    assert result.domain == "CORP.LOCAL"
    assert result.host == "10.10.10.5"
    assert result.json_output_path == "/tmp/fake/bloodhound.out"
    assert result.raw_output_path == "/tmp/fake/bloodhound.out"
    assert result.duration_sec == 12.5
    # Per brief: no in-memory parsing — computers/users/sessions stay empty.
    assert result.computers == []
    assert result.users == []
    assert result.sessions == []
