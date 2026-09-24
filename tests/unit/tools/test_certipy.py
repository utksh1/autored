"""Tests for the certipy tool wrapper (Phase 4, Task 5).

Same Phase 4 stub pattern as the sibling mimikatz / secretsdump wrappers
— ``_build_certipy_cmd`` is exercised directly (so the CLI argv contract
has a stable, reviewable surface) and the ``certipy`` ``@tool`` is exercised
end-to-end via ``.ainvoke({...})`` with ``_save_raw`` mocked so the test
never touches the network or disk. Per the T5 brief, ``certipy`` constructs
the certipy command string and saves it; real execution is deferred to the
Phase 6 FootholdSessionManager.
"""
from __future__ import annotations

import pytest

from autored.config import load_roe
from autored.roe_guard import register_roe
from autored.tools.certipy import CertipyResult, _build_certipy_cmd, certipy


def test_build_certipy_cmd_find():
    """Built argv contains all the brief-mandated flags + values in the
    canonical certipy order — note ``-u`` takes ``user@DOMAIN`` (UPN form),
    not the bare username."""
    cmd = _build_certipy_cmd(
        action="find",
        username="user",
        password="pass",
        domain="CORP.LOCAL",
        target="10.10.10.5",
    )
    assert "certipy" in cmd[0]
    assert "find" in cmd
    assert "-u" in cmd
    assert "user@CORP.LOCAL" in cmd
    assert "-p" in cmd
    assert "pass" in cmd
    # The DC IP is passed via -dc-ip so certipy knows which LDAP endpoint
    # to bind to (matters in multi-DC forests where the DNS A record does
    # not point at the PDC).
    assert "-dc-ip" in cmd
    assert "10.10.10.5" in cmd


def test_certipy_result_model():
    """The result model accepts the brief-specified fields + defaults."""
    r = CertipyResult(
        action="find",
        target="10.10.10.5",
        vulnerable_templates=[],
        raw_output_path="",
    )
    assert r.action == "find"
    assert r.target == "10.10.10.5"
    assert r.vulnerable_templates == []
    assert r.raw_output_path == ""
    assert r.duration_sec == 0.0


@pytest.mark.asyncio
async def test_certipy_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, monkeypatch
):
    """Integration test: call the decorated tool end-to-end via .ainvoke().

    Same regression-catcher rationale as the sibling mimikatz / secretsdump
    integration tests — ``@tool`` outermost + ``@roe_guard`` inner per
    Ruling 1. Per the T5 brief, ``certipy`` does NOT actually execute
    subprocess — it constructs the certipy command string and persists it
    via ``_save_raw`` so the Phase 6 FootholdSessionManager can replay it.
    """
    roe = load_roe(sandbox_roe_yaml)
    register_roe("certipy-int", roe)

    async def fake_save_raw(*args, **kwargs):
        return "/tmp/fake/certipy_cmd.out"

    monkeypatch.setattr("autored.tools.certipy._save_raw", fake_save_raw)

    result = await certipy.ainvoke(
        {
            "action": "find",
            "username": "svc_scan",
            "password": "P@ssw0rd!",
            "domain": "CORP.LOCAL",
            "target": "10.10.10.5",
            "engagement_id": "certipy-int",
        }
    )

    assert isinstance(result, CertipyResult)
    assert result.action == "find"
    assert result.target == "10.10.10.5"
    assert result.domain == "CORP.LOCAL"
    assert result.username == "svc_scan"
    # Phase 4 stub: raw_output_path is set (command was saved) but
    # vulnerable_templates is empty because the tool did not execute.
    assert result.raw_output_path == "/tmp/fake/certipy_cmd.out"
    assert result.vulnerable_templates == []
