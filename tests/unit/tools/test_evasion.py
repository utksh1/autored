"""Tests for the evasion tool wrappers (Phase 4, Task 7).

Four evasion techniques live in ``autored/tools.evasion`` — three of
them (``amsi_bypass``, ``log_clear``, ``defender_disable``) have full
``@tool`` wrappers and the fourth (``etw_patch``) is exposed only as a
``_build_*`` helper per the Phase 4 plan analysis (its execution
surface is the foothold shell, not the operator — Phase 6 will wire it
into the FootholdSessionManager when the session manager exists).

The three brief-mandated tests cover ``_build_amsi_bypass``,
``_build_log_clear``, and the ``EvasionResult`` model; three
integration tests cover the decorator-stacking regression catcher
(Ruling 1) for each ``@tool`` wrapper.
"""
from __future__ import annotations

import pytest

from autored.config import load_roe
from autored.roe_guard import register_roe
from autored.tools.evasion import (
    EvasionResult,
    _build_amsi_bypass,
    _build_log_clear,
    amsi_bypass,
    defender_disable,
    log_clear,
)


def test_build_amsi_bypass():
    """``_build_amsi_bypass`` returns a PowerShell argv list that patches
    amsi.dll's ``amsiInitFailed`` field via reflection (the canonical
    RastaMouse bypass)."""
    cmd = _build_amsi_bypass()
    assert len(cmd) > 0
    # Should be a PowerShell command that patches amsi.dll
    cmd_str = " ".join(cmd)
    assert "amsi" in cmd_str.lower() or "reflection" in cmd_str.lower()


def test_build_log_clear():
    """``_build_log_clear("all")`` returns a PowerShell argv list that
    clears the Security / System / Application event logs via ``wevtutil
    cl``."""
    cmd = _build_log_clear("all")  # all = Security, System, Application
    cmd_str = " ".join(cmd)
    assert "wevtutil" in cmd_str or "Clear-EventLog" in cmd_str


def test_evasion_result_model():
    """The result model accepts the brief-specified fields + defaults."""
    r = EvasionResult(
        technique="amsi_bypass",
        host_ip="10.10.10.5",
        success=True,
        command="...",
    )
    assert r.technique == "amsi_bypass"
    assert r.host_ip == "10.10.10.5"
    assert r.success is True
    assert r.command == "..."


@pytest.mark.asyncio
async def test_amsi_bypass_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, monkeypatch
):
    """Integration test: ``@tool`` outer + ``@roe_guard`` inner per Ruling 1.

    Per the T7 brief, ``amsi_bypass`` does NOT actually execute — it
    constructs the PowerShell command string and saves it via ``_save_raw``
    so the Phase 6 FootholdSessionManager can replay it on the foothold.
    """
    roe = load_roe(sandbox_roe_yaml)
    register_roe("amsi-int", roe)

    async def fake_save_raw(*args, **kwargs):
        return "/tmp/fake/amsi_bypass_cmd.out"

    monkeypatch.setattr("autored.tools.evasion._save_raw", fake_save_raw)

    result = await amsi_bypass.ainvoke(
        {
            "host_ip": "10.10.10.5",
            "engagement_id": "amsi-int",
        }
    )

    assert isinstance(result, EvasionResult)
    assert result.technique == "amsi_bypass"
    assert result.host_ip == "10.10.10.5"
    assert result.success is True
    assert "amsi" in result.command.lower() or "reflection" in result.command.lower()
    assert result.raw_output_path == "/tmp/fake/amsi_bypass_cmd.out"


@pytest.mark.asyncio
async def test_log_clear_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, monkeypatch
):
    """Integration test for ``log_clear`` — same rationale as
    ``test_amsi_bypass_ainvoke_works_with_roe_guard`` above."""
    roe = load_roe(sandbox_roe_yaml)
    register_roe("logclear-int", roe)

    async def fake_save_raw(*args, **kwargs):
        return "/tmp/fake/log_clear_cmd.out"

    monkeypatch.setattr("autored.tools.evasion._save_raw", fake_save_raw)

    result = await log_clear.ainvoke(
        {
            "host_ip": "10.10.10.5",
            "log_type": "all",
            "engagement_id": "logclear-int",
        }
    )

    assert isinstance(result, EvasionResult)
    assert result.technique == "log_clear"
    assert result.host_ip == "10.10.10.5"
    assert result.success is True
    assert "wevtutil" in result.command or "Clear-EventLog" in result.command
    assert result.raw_output_path == "/tmp/fake/log_clear_cmd.out"


@pytest.mark.asyncio
async def test_defender_disable_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, monkeypatch
):
    """Integration test for ``defender_disable`` — same rationale as
    ``test_amsi_bypass_ainvoke_works_with_roe_guard`` above."""
    roe = load_roe(sandbox_roe_yaml)
    register_roe("defender-int", roe)

    async def fake_save_raw(*args, **kwargs):
        return "/tmp/fake/defender_disable_cmd.out"

    monkeypatch.setattr("autored.tools.evasion._save_raw", fake_save_raw)

    result = await defender_disable.ainvoke(
        {
            "host_ip": "10.10.10.5",
            "engagement_id": "defender-int",
        }
    )

    assert isinstance(result, EvasionResult)
    assert result.technique == "defender_disable"
    assert result.host_ip == "10.10.10.5"
    assert result.success is True
    assert "MpPreference" in result.command  # Set-MpPreference cmdlet
    assert result.raw_output_path == "/tmp/fake/defender_disable_cmd.out"
