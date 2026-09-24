"""Unit tests for impacket remote-exec tool wrappers (Phase 5 Task 2).

Only the pure helpers (_build_*_cmd, _parse_*_output) and the Result
model are exercised by the brief-mandated tests — the @roe_guard-decorated
entrypoints require a registered RoE and a live subprocess, which the
three integration tests at the bottom cover (one per wrapper, mocking
both ``run_subprocess`` and ``_save_raw``).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from autored.config import load_roe
from autored.roe_guard import register_roe
from autored.subprocess_runner import SubprocessResult
from autored.tools.impacket_remote import (
    ImpacketRemoteResult,
    _build_impacket_cmd,
    _parse_impacket_output,
    impacket_wmiexec,
    impacket_psexec,
    impacket_smbexec,
)

FIXTURES = Path(__file__).parents[2] / "fixtures"


def _sub(result_text: str, returncode: int = 0) -> SubprocessResult:
    return SubprocessResult(
        stdout=result_text, stderr="", returncode=returncode,
        duration_sec=1.0, command="wmiexec.py",
    )


def test_build_cmd_with_password():
    cmd = _build_impacket_cmd(
        "wmiexec", "administrator", "Password1!", "", "192.168.56.11", "whoami",
    )
    assert cmd[0] == "wmiexec.py"
    assert "administrator:Password1!@192.168.56.11" in cmd
    assert cmd[-1] == "whoami"
    assert "-hashes" not in cmd


def test_build_cmd_with_nthash():
    cmd = _build_impacket_cmd(
        "psexec", "administrator", "", "31d6cfe0d16ae931b73c59d7e0c089c0",
        "192.168.56.11", "whoami",
    )
    assert "-hashes" in cmd
    assert ":31d6cfe0d16ae931b73c59d7e0c089c0" in cmd
    assert "administrator@192.168.56.11" in cmd
    assert "Password1!" not in " ".join(cmd)


def test_build_smbexec_cmd_shape():
    cmd = _build_impacket_cmd(
        "smbexec", "bob", "pass", "", "10.0.0.2", "id",
    )
    assert cmd[0] == "smbexec.py"
    assert "bob:pass@10.0.0.2" in cmd


def test_parse_success_output():
    text = (FIXTURES / "impacket_wmiexec_output.txt").read_text()
    res = _parse_impacket_output(_sub(text), "192.168.56.11", "wmiexec", "whoami", "")
    assert res.success is True
    assert res.host_ip == "192.168.56.11"
    assert "administrator" in res.output


def test_parse_failure_logon_failure():
    text = (FIXTURES / "impacket_wmiexec_failure.txt").read_text()
    res = _parse_impacket_output(_sub(text), "192.168.56.11", "wmiexec", "whoami", "")
    assert res.success is False


def test_parse_failure_nonzero_returncode():
    res = _parse_impacket_output(
        _sub("whatever", returncode=1), "10.0.0.2", "wmiexec", "id", "",
    )
    assert res.success is False


def test_parse_failure_session_exception():
    res = _parse_impacket_output(
        _sub("[!] SessionError: something broke"), "10.0.0.2", "smbexec", "id", "",
    )
    assert res.success is False


def test_result_model_defaults():
    r = ImpacketRemoteResult(
        host_ip="h", method="wmiexec", command_executed="whoami", output="o",
        success=True,
    )
    assert r.raw_output_path == ""
    assert r.duration_sec == 0.0


# ---------------------------------------------------------------------------
# Integration tests — one per @tool wrapper, mocking run_subprocess +
# _save_raw. Each verifies the @tool OUTER + @roe_guard INNER decorator
# order (Ruling 1) and that the wrapper returns a properly typed
# ImpacketRemoteResult end-to-end.
# ---------------------------------------------------------------------------


def _fake_subprocess_factory(stdout: str, returncode: int = 0):
    async def fake_run_subprocess(cmd, timeout=300):
        return SubprocessResult(
            stdout=stdout, stderr="", returncode=returncode,
            duration_sec=1.0, command=" ".join(cmd),
        )
    return fake_run_subprocess


async def _fake_save_raw(*args, **kwargs):
    return "/tmp/fake/impacket_remote.out"


@pytest.mark.asyncio
async def test_impacket_wmiexec_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, monkeypatch
):
    """Integration test: ``@tool`` outer + ``@roe_guard`` inner per Ruling 1.

    Drives the decorated wrapper end-to-end via ``.ainvoke()`` with the
    subprocess runner + raw-saver mocked, so the test does not require
    a live impacket binary or network target.
    """
    roe = load_roe(sandbox_roe_yaml)
    register_roe("wmiexec-int", roe)

    text = (FIXTURES / "impacket_wmiexec_output.txt").read_text()
    monkeypatch.setattr(
        "autored.tools.impacket_remote.run_subprocess",
        _fake_subprocess_factory(text),
    )
    monkeypatch.setattr("autored.tools.impacket_remote._save_raw", _fake_save_raw)

    result = await impacket_wmiexec.ainvoke(
        {
            "username": "administrator",
            "password": "P@ssw0rd!",
            "nthash": "",
            "target": "192.168.56.11",
            "command": "whoami",
            "engagement_id": "wmiexec-int",
        }
    )

    assert isinstance(result, ImpacketRemoteResult)
    assert result.host_ip == "192.168.56.11"
    assert result.method == "wmiexec"
    assert result.success is True
    assert "administrator" in result.output
    assert result.raw_output_path == "/tmp/fake/impacket_remote.out"


@pytest.mark.asyncio
async def test_impacket_psexec_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, monkeypatch
):
    """Integration test for ``impacket_psexec`` — same rationale as wmiexec."""
    roe = load_roe(sandbox_roe_yaml)
    register_roe("psexec-int", roe)

    monkeypatch.setattr(
        "autored.tools.impacket_remote.run_subprocess",
        _fake_subprocess_factory("goaad\\administrator", returncode=0),
    )
    monkeypatch.setattr("autored.tools.impacket_remote._save_raw", _fake_save_raw)

    result = await impacket_psexec.ainvoke(
        {
            "username": "administrator",
            "password": "",
            "nthash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "target": "192.168.56.11",
            "command": "whoami",
            "engagement_id": "psexec-int",
        }
    )

    assert isinstance(result, ImpacketRemoteResult)
    assert result.method == "psexec"
    assert result.success is True


@pytest.mark.asyncio
async def test_impacket_smbexec_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, monkeypatch
):
    """Integration test for ``impacket_smbexec`` — same rationale as wmiexec."""
    roe = load_roe(sandbox_roe_yaml)
    register_roe("smbexec-int", roe)

    text = (FIXTURES / "impacket_wmiexec_failure.txt").read_text()
    monkeypatch.setattr(
        "autored.tools.impacket_remote.run_subprocess",
        _fake_subprocess_factory(text, returncode=0),
    )
    monkeypatch.setattr("autored.tools.impacket_remote._save_raw", _fake_save_raw)

    result = await impacket_smbexec.ainvoke(
        {
            "username": "administrator",
            "password": "wrongpw",
            "nthash": "",
            "target": "192.168.56.11",
            "command": "id",
            "engagement_id": "smbexec-int",
        }
    )

    assert isinstance(result, ImpacketRemoteResult)
    assert result.method == "smbexec"
    # Fixture contains STATUS_LOGON_FAILURE → success must be False.
    assert result.success is False
