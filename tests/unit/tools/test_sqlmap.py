"""Tests for the sqlmap tool wrapper (Phase 3, Task 3)."""
from __future__ import annotations

import pytest

from autored.config import load_roe
from autored.roe_guard import register_roe
from autored.subprocess_runner import SubprocessResult
from autored.tools.sqlmap import (
    InjectionPoint,
    SqlmapResult,
    _build_sqlmap_cmd,
    _parse_sqlmap_output,
    sqlmap_run,
)


def test_build_sqlmap_cmd_basic():
    cmd = _build_sqlmap_cmd("http://10.10.10.5/page?id=1", None, None)
    assert "sqlmap" in cmd[0]
    assert "-u" in cmd
    assert "http://10.10.10.5/page?id=1" in cmd
    assert "--batch" in cmd


def test_build_sqlmap_cmd_with_options():
    cmd = _build_sqlmap_cmd("http://target", ["--forms", "--level=3"], "/tmp/output")
    assert "--forms" in cmd
    assert "--level=3" in cmd
    assert "--output-dir" in cmd
    assert "/tmp/output" in cmd


def test_parse_sqlmap_output_vulnerable(fixtures_dir):
    text = (fixtures_dir / "sqlmap_output.txt").read_text()
    result = _parse_sqlmap_output(text, "http://target")
    assert result.vulnerable is True
    assert len(result.injection_points) >= 1
    assert "boolean-based blind" in result.injection_points[0].type
    assert result.dbms == "MySQL >= 5.0"


def test_parse_sqlmap_output_not_vulnerable():
    text = "all tested parameters do not appear to be injectable"
    result = _parse_sqlmap_output(text, "http://target")
    assert result.vulnerable is False
    assert result.injection_points == []


@pytest.mark.asyncio
async def test_sqlmap_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, fixtures_dir, monkeypatch
):
    """Integration test: call the decorated tool end-to-end via .ainvoke().

    Regression catcher for the decorator-stacking bug (Ruling 1 in the SDD
    ledger): the brief's spec'd ``@roe_guard`` over ``@tool`` order produced
    a StructuredTool that was not callable via ``.ainvoke({...})``
    (``TypeError: 'StructuredTool' object is not callable``). With the
    swapped order (``@tool`` outermost, ``@roe_guard`` inner), the
    StructuredTool's underlying coroutine is a regular async def, and
    ``.ainvoke({...})`` dispatches correctly through the RoE wrapper.

    Note: ``_save_raw`` is imported into ``sqlmap``'s namespace via
    ``from autored.tools.nmap import _save_raw``, so the patch target must
    be ``autored.tools.sqlmap._save_raw`` to intercept the call from
    inside ``sqlmap_run``.
    """
    # 1. Register a RoE for the test engagement.
    roe = load_roe(sandbox_roe_yaml)
    register_roe("sqlmap-int", roe)

    # 2. Mock run_subprocess to return the fixture stdout.
    sqlmap_text = (fixtures_dir / "sqlmap_output.txt").read_text()

    async def fake_run_subprocess(cmd, timeout=600):
        return SubprocessResult(
            stdout=sqlmap_text,
            stderr="",
            returncode=0,
            duration_sec=0.4,
            command=" ".join(cmd),
        )

    monkeypatch.setattr("autored.tools.sqlmap.run_subprocess", fake_run_subprocess)

    # 3. Mock _save_raw to a no-op so the test doesn't touch disk.
    async def fake_save_raw(*args, **kwargs):
        return ""

    monkeypatch.setattr("autored.tools.sqlmap._save_raw", fake_save_raw)

    # 4. Call the tool via .ainvoke({...}).
    result = await sqlmap_run.ainvoke(
        {
            "url": "http://10.10.10.5/page?id=1",
            "options": ["--level=3"],
            "engagement_id": "sqlmap-int",
        }
    )

    # 5. Assert the returned object is the right Pydantic model with the
    #    expected fields populated.
    assert isinstance(result, SqlmapResult)
    assert result.url == "http://10.10.10.5/page?id=1"
    assert result.vulnerable is True
    assert len(result.injection_points) >= 1
    assert isinstance(result.injection_points[0], InjectionPoint)
    assert result.injection_points[0].parameter == "id"
    assert result.injection_points[0].method == "GET"
    assert "boolean-based blind" in result.injection_points[0].type
    assert result.dbms == "MySQL >= 5.0"
