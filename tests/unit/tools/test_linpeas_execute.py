"""Phase 6 Task 2 — linpeas/winpeas/mimikatz execute via installed session."""
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from autored.config import load_roe
from autored.foothold_session import FootholdCommandResult
from autored.models import Foothold
from autored.roe_guard import register_roe

FIXTURES = Path(__file__).parents[2] / "fixtures"


def _register_e1_roe(sandbox_roe_yaml: str) -> None:
    """Register a permissive RoE for engagement ``e1`` so the
    ``@roe_guard(allowed_categories=["read_only"])``-decorated enum
    wrappers accept the call. Mirrors the existing Phase 4 pattern in
    ``test_linpeas.py`` / ``test_winpeas.py`` / ``test_mimikatz.py``.
    """
    roe = load_roe(sandbox_roe_yaml)
    register_roe("e1", roe)


def _foothold(access_type: str = "ssh") -> Foothold:
    return Foothold(
        id="f-1", host_ip="10.0.0.5", username="root", context="user",
        method="ssh_brute", access_type=access_type,
        evidence_path="evidence/f1.txt",
        established_at=datetime.utcnow(), hypothesis_rank=1,
    )


def _manager(stdout: str) -> MagicMock:
    mgr = MagicMock()
    mgr.find_foothold = MagicMock(return_value=_foothold())
    mgr.execute = AsyncMock(return_value=FootholdCommandResult(
        command="linpeas", stdout=stdout, stderr="",
        returncode=0, duration_sec=2.0, success=True,
    ))
    return mgr


async def test_linpeas_executes_and_parses_when_manager_installed(
    monkeypatch, tmp_path, sandbox_roe_yaml,
):
    _register_e1_roe(sandbox_roe_yaml)
    import autored.tools.linpeas as lin

    # _save_raw writes into engagements/<id>/raw — point it at tmp_path
    async def fake_save_raw(tool, target, stdout, stderr, engagement_id):
        p = tmp_path / f"{tool}.out"
        p.write_text(stdout)
        return str(p)

    monkeypatch.setattr(lin, "_save_raw", fake_save_raw)
    monkeypatch.setattr(lin, "get_installed", lambda: _manager(
        (FIXTURES / "linpeas_sample_output.txt").read_text()))

    result = await lin.linpeas_run.ainvoke({
        "foothold_id": "f-1", "host_ip": "10.0.0.5", "engagement_id": "e1",
    })
    assert result.suid_binaries == [
        "rwxr-xr-x 1 root root 40K Sep  1 2024 /usr/bin/find",
        "rwsr-xr-x 1 root root 59K Oct  2 2024 /usr/bin/passwd",
    ]
    assert "CVE-2021-4034" in result.cves
    assert len(result.cron_jobs) == 2
    assert result.command.startswith("curl -sL")
    assert result.duration_sec == 2.0


async def test_winpeas_executes_and_parses(monkeypatch, tmp_path, sandbox_roe_yaml):
    _register_e1_roe(sandbox_roe_yaml)
    import autored.tools.winpeas as wp

    async def fake_save_raw(tool, target, stdout, stderr, engagement_id):
        p = tmp_path / f"{tool}.out"
        p.write_text(stdout)
        return str(p)

    monkeypatch.setattr(wp, "_save_raw", fake_save_raw)
    monkeypatch.setattr(wp, "get_installed", lambda: _manager(
        (FIXTURES / "winpeas_sample_output.txt").read_text()))

    result = await wp.winpeas_run.ainvoke({
        "foothold_id": "f-1", "host_ip": "10.0.0.5", "engagement_id": "e1",
    })
    assert result.autologon_credentials == [{
        "domain": "GOAD", "username": "administrator", "password": "Passw0rd!",
    }]
    assert any("spoolsv" in s for s in result.modifiable_services)


async def test_mimikatz_executes_and_parses(monkeypatch, tmp_path, sandbox_roe_yaml):
    _register_e1_roe(sandbox_roe_yaml)
    import autored.tools.mimikatz as mk

    async def fake_save_raw(tool, target, stdout, stderr, engagement_id):
        p = tmp_path / f"{tool}.out"
        p.write_text(stdout)
        return str(p)

    monkeypatch.setattr(mk, "_save_raw", fake_save_raw)
    monkeypatch.setattr(mk, "get_installed", lambda: _manager(
        (FIXTURES / "mimikatz_sample_output.txt").read_text()))

    result = await mk.mimikatz_wrapper.ainvoke({
        "foothold_id": "f-1", "host_ip": "10.0.0.5", "engagement_id": "e1",
    })
    by_provider = {c["provider"]: c for c in result.credentials}
    assert by_provider["msv"]["ntlm"] == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert by_provider["wdigest"]["password"] == "Password1!"


async def test_linpeas_falls_back_when_no_manager(
    monkeypatch, tmp_path, sandbox_roe_yaml,
):
    """No installed manager → Phase 4 evidence-string behavior, empty result."""
    _register_e1_roe(sandbox_roe_yaml)
    import autored.tools.linpeas as lin

    async def fake_save_raw(tool, target, stdout, stderr, engagement_id):
        p = tmp_path / f"{tool}.out"
        p.write_text(stdout)
        return str(p)

    monkeypatch.setattr(lin, "_save_raw", fake_save_raw)
    monkeypatch.setattr(lin, "get_installed", lambda: None)

    result = await lin.linpeas_run.ainvoke({
        "foothold_id": "f-1", "host_ip": "10.0.0.5", "engagement_id": "e1",
    })
    assert result.suid_binaries == []
    assert result.command.startswith("curl -sL")


async def test_linpeas_falls_back_when_execution_fails(
    monkeypatch, tmp_path, sandbox_roe_yaml,
):
    """Manager installed but execute fails → evidence-string fallback."""
    _register_e1_roe(sandbox_roe_yaml)
    import autored.tools.linpeas as lin

    async def fake_save_raw(tool, target, stdout, stderr, engagement_id):
        p = tmp_path / f"{tool}.out"
        p.write_text(stdout)
        return str(p)

    mgr = MagicMock()
    mgr.find_foothold = MagicMock(return_value=_foothold())
    mgr.execute = AsyncMock(return_value=FootholdCommandResult(
        command="linpeas", stdout="", stderr="connection refused",
        returncode=255, duration_sec=0.1, success=False,
    ))
    monkeypatch.setattr(lin, "_save_raw", fake_save_raw)
    monkeypatch.setattr(lin, "get_installed", lambda: mgr)

    result = await lin.linpeas_run.ainvoke({
        "foothold_id": "f-1", "host_ip": "10.0.0.5", "engagement_id": "e1",
    })
    assert result.suid_binaries == []  # nothing parsed — but no crash either
