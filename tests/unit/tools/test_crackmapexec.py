"""Unit tests for the crackmapexec tool wrapper (Phase 5 Task 3).

Note: ``autored.tools.crackmapexec`` resolves to the StructuredTool
exported by ``autored/tools/__init__.py`` (function name shadows the
module name). To monkeypatch module-level names like
``run_subprocess``, look the module up via ``sys.modules`` — that
returns the real module object regardless of package-attribute
shadowing.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from autored.config import load_roe
from autored.roe_guard import register_roe
from autored.subprocess_runner import SubprocessResult
from autored.tools.crackmapexec import (
    CrackmapexecResult,
    _build_cme_cmd,
    _parse_cme_output,
    crackmapexec,
)

cme_mod = sys.modules["autored.tools.crackmapexec"]

FIXTURES = Path(__file__).parents[2] / "fixtures"


def _sub(text: str, returncode: int = 0) -> SubprocessResult:
    return SubprocessResult(
        stdout=text, stderr="", returncode=returncode,
        duration_sec=2.0, command="crackmapexec",
    )


def test_build_cmd_with_hash():
    cmd = _build_cme_cmd(
        "smb", "192.168.56.22", "administrator",
        password="", nthash="31d6cfe0d16ae931b73c59d7e0c089c0",
    )
    assert cmd[:3] == ["crackmapexec", "smb", "192.168.56.22"]
    assert "-u" in cmd and "administrator" in cmd
    assert "-H" in cmd and "31d6cfe0d16ae931b73c59d7e0c089c0" in cmd
    assert "-p" not in cmd


def test_build_cmd_with_password():
    cmd = _build_cme_cmd("smb", "10.0.0.2", "bob", password="pw", nthash="")
    assert "-p" in cmd and "pw" in cmd
    assert "-H" not in cmd


def test_parse_pwned_output():
    text = (FIXTURES / "crackmapexec_goad.txt").read_text()
    res = _parse_cme_output(_sub(text), "192.168.56.22", "smb", "administrator", "")
    assert res.success is True
    assert res.pwned is True
    assert res.username == "administrator"


def test_parse_logon_failure():
    text = (
        "SMB         10.0.0.2     445    HOST  [-] NORTH\\bob:bad "
        "(STATUS_LOGON_FAILURE)"
    )
    res = _parse_cme_output(_sub(text), "10.0.0.2", "smb", "bob", "")
    assert res.success is False
    assert res.pwned is False


def test_parse_auth_ok_not_admin():
    # [+] auth but no (Pwn3d!) → cred works, but no admin
    text = "SMB         10.0.0.2     445    HOST  [+] NORTH\\bob:pw"
    res = _parse_cme_output(_sub(text), "10.0.0.2", "smb", "bob", "")
    assert res.success is True
    assert res.pwned is False


def test_parse_nonzero_returncode_is_failure():
    res = _parse_cme_output(_sub("anything", returncode=1), "10.0.0.2", "smb", "u", "")
    assert res.success is False


def test_result_model_defaults():
    r = CrackmapexecResult(
        host_ip="h", protocol="smb", username="u",
        success=True, pwned=True, output="o",
    )
    assert r.raw_output_path == ""
    assert r.duration_sec == 0.0


@pytest.mark.asyncio
async def test_crackmapexec_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, monkeypatch
):
    """Integration test: ``@tool`` outer + ``@roe_guard`` inner per Ruling 1.

    Mocks ``run_subprocess`` + ``_save_raw`` so no live CME binary or
    network target is required. Feeds the GoAD fixture through the
    end-to-end wrapper to confirm the parser path is exercised by the
    @tool entrypoint (not just by the helper unit tests above).
    """
    roe = load_roe(sandbox_roe_yaml)
    register_roe("cme-int", roe)

    text = (FIXTURES / "crackmapexec_goad.txt").read_text()

    async def fake_run_subprocess(cmd, timeout=180):
        return SubprocessResult(
            stdout=text, stderr="", returncode=0,
            duration_sec=2.0, command=" ".join(cmd),
        )

    async def fake_save_raw(*args, **kwargs):
        return "/tmp/fake/crackmapexec.out"

    monkeypatch.setattr(cme_mod, "run_subprocess", fake_run_subprocess)
    monkeypatch.setattr(cme_mod, "_save_raw", fake_save_raw)

    result = await crackmapexec.ainvoke(
        {
            "protocol": "smb",
            "target": "192.168.56.22",
            "username": "administrator",
            "password": "",
            "nthash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "engagement_id": "cme-int",
        }
    )

    assert isinstance(result, CrackmapexecResult)
    assert result.host_ip == "192.168.56.22"
    assert result.protocol == "smb"
    assert result.username == "administrator"
    assert result.success is True
    assert result.pwned is True
    assert result.raw_output_path == "/tmp/fake/crackmapexec.out"
