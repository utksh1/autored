"""Unit tests for cleanup tools (Phase 5 Task 5)."""
from __future__ import annotations

from pathlib import Path

import pytest

from autored.config import load_roe
from autored.roe_guard import register_roe
from autored.subprocess_runner import SubprocessResult
from autored.tools.cleanup import (
    CleanupExecutionResult,
    CleanupVerificationResult,
    _artifact_absent,
    _build_remote_cmd,
    _build_verify_command,
    cleanup_execute,
    cleanup_verify,
)

FIXTURES = Path(__file__).parents[2] / "fixtures"


def _sub(text: str, returncode: int = 0) -> SubprocessResult:
    return SubprocessResult(
        stdout=text, stderr="", returncode=returncode,
        duration_sec=1.0, command="cleanup",
    )


# ---------------------------------------------------------------------------
# _build_remote_cmd — dispatch on transport (impacket_wmiexec vs ssh)
# ---------------------------------------------------------------------------


def test_build_remote_cmd_wmiexec_transport():
    cmd = _build_remote_cmd(
        "impacket_wmiexec", "10.0.0.2", "administrator", "", "abc123",
        "schtasks /delete /tn AutoRedUpdate /f",
    )
    assert cmd[0] == "wmiexec.py"
    assert "-hashes" in cmd
    assert "administrator@10.0.0.2" in cmd
    assert cmd[-1].startswith("schtasks /delete")


def test_build_remote_cmd_ssh_transport():
    cmd = _build_remote_cmd(
        "ssh", "10.0.0.3", "root", "pw", "", "crontab -r",
    )
    assert cmd[:2] == ["sshpass", "-p"]
    assert "root@10.0.0.3" in cmd
    assert cmd[-1] == "crontab -r"


# ---------------------------------------------------------------------------
# _build_verify_command — per-artifact-method absence probes
# ---------------------------------------------------------------------------


def test_build_verify_command_scheduled_task():
    cmd = _build_verify_command(
        "scheduled_task", {"task_name": "AutoRedUpdate"},
    )
    assert "schtasks /query" in cmd
    assert "AutoRedUpdate" in cmd


def test_build_verify_command_registry_run():
    cmd = _build_verify_command(
        "registry_run", {"key_path": "HKCU\\...\\Run", "value_name": "AutoRed"},
    )
    assert "reg query" in cmd
    assert "AutoRed" in cmd


def test_build_verify_command_cron():
    cmd = _build_verify_command("cron", {"command": "bash -i"})
    assert "crontab -l" in cmd
    assert "bash -i" in cmd


def test_build_verify_command_unknown_method_falls_back():
    cmd = _build_verify_command("wmi_subscription", {})
    assert cmd  # non-empty fallback, never crashes


# ---------------------------------------------------------------------------
# _artifact_absent — Windows markers + grep-style absence
# ---------------------------------------------------------------------------


def test_artifact_absent_windows_not_found_marker():
    text = "ERROR: The system cannot find the file specified."
    assert _artifact_absent("scheduled_task", text, 1) is True


def test_artifact_absent_registry_marker():
    text = "The system was unable to find the specified registry key or value."
    assert _artifact_absent("registry_run", text, 1) is True


def test_artifact_absent_still_present():
    text = "TaskName: AutoRedUpdate  Next Run: tomorrow"
    assert _artifact_absent("scheduled_task", text, 0) is False


def test_artifact_absent_grep_style_nonzero_exit():
    # grep-based verify (cron/systemd/ssh keys): rc 1 = no match = gone
    assert _artifact_absent("cron", "", 1) is True
    assert _artifact_absent("cron", "bash -i >& ...", 0) is False


# ---------------------------------------------------------------------------
# Integration tests — one per @tool wrapper, mocking run_subprocess +
# _save_raw. Each verifies the @tool OUTER + @roe_guard INNER decorator
# order (Ruling 1) and that the wrapper returns a properly typed result
# end-to-end.
# ---------------------------------------------------------------------------


def _fake_subprocess_factory(stdout: str, stderr: str = "", returncode: int = 0):
    async def fake_run_subprocess(cmd, timeout=180):
        return SubprocessResult(
            stdout=stdout, stderr=stderr, returncode=returncode,
            duration_sec=1.0, command=" ".join(cmd),
        )
    return fake_run_subprocess


async def _fake_save_raw(*args, **kwargs):
    return "/tmp/fake/cleanup.out"


@pytest.mark.asyncio
async def test_cleanup_execute_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, monkeypatch
):
    """Integration test: ``@tool`` outer + ``@roe_guard`` inner per Ruling 1.

    Drives the decorated wrapper end-to-end via ``.ainvoke()`` with the
    subprocess runner + raw-saver mocked, so the test does not require
    a live impacket binary or network target.
    """
    roe = load_roe(sandbox_roe_yaml)
    register_roe("cleanup-exec-int", roe)

    text = (FIXTURES / "impacket_wmiexec_output.txt").read_text()
    monkeypatch.setattr(
        "autored.tools.cleanup.run_subprocess",
        _fake_subprocess_factory(text),
    )
    monkeypatch.setattr("autored.tools.cleanup._save_raw", _fake_save_raw)

    result = await cleanup_execute.ainvoke(
        {
            "host_ip": "192.168.56.11",
            "removal_command": "schtasks /delete /tn AutoRedUpdate /f",
            "transport": "impacket_wmiexec",
            "username": "administrator",
            "password": "P@ssw0rd!",
            "nthash": "",
            "engagement_id": "cleanup-exec-int",
        }
    )

    assert isinstance(result, CleanupExecutionResult)
    assert result.host_ip == "192.168.56.11"
    assert result.transport == "impacket_wmiexec"
    assert result.success is True
    assert result.removal_command.startswith("schtasks /delete")
    assert result.raw_output_path == "/tmp/fake/cleanup.out"


@pytest.mark.asyncio
async def test_cleanup_verify_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, monkeypatch
):
    """Integration test for ``cleanup_verify`` — verifies absence parsing.

    The mocked subprocess returns Windows "cannot find" text, which
    ``_artifact_absent`` must recognise as proof the scheduled task is
    gone → ``verified`` True.
    """
    roe = load_roe(sandbox_roe_yaml)
    register_roe("cleanup-verify-int", roe)

    # Re-scan output for a scheduled task that has been deleted.
    absent_text = "ERROR: The system cannot find the file specified."
    monkeypatch.setattr(
        "autored.tools.cleanup.run_subprocess",
        _fake_subprocess_factory(absent_text, returncode=1),
    )
    monkeypatch.setattr("autored.tools.cleanup._save_raw", _fake_save_raw)

    result = await cleanup_verify.ainvoke(
        {
            "host_ip": "192.168.56.11",
            "verify_command": 'schtasks /query /tn "AutoRedUpdate"',
            "method": "scheduled_task",
            "transport": "impacket_wmiexec",
            "username": "administrator",
            "password": "P@ssw0rd!",
            "nthash": "",
            "engagement_id": "cleanup-verify-int",
        }
    )

    assert isinstance(result, CleanupVerificationResult)
    assert result.host_ip == "192.168.56.11"
    assert result.verified is True
    assert result.transport == "impacket_wmiexec"
    assert "AutoRedUpdate" in result.verify_command
    assert result.raw_output_path == "/tmp/fake/cleanup.out"
