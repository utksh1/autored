"""Tests for the hydra tool wrapper (Phase 3, Task 4)."""
from __future__ import annotations

import pytest

from autored.config import load_roe
from autored.roe_guard import register_roe
from autored.subprocess_runner import SubprocessResult
from autored.tools.hydra import (
    BruteCredential,
    BruteResult,
    _build_hydra_cmd,
    _parse_hydra_output,
    hydra_brute,
)


def test_build_hydra_cmd():
    cmd = _build_hydra_cmd("10.10.10.5", "ssh", "/tmp/users.txt", "/tmp/pass.txt")
    assert "hydra" in cmd[0]
    assert "-L" in cmd
    assert "/tmp/users.txt" in cmd
    assert "-P" in cmd
    assert "/tmp/pass.txt" in cmd
    assert "ssh://10.10.10.5" in cmd


def test_parse_hydra_output_found(fixtures_dir):
    text = (fixtures_dir / "hydra_output.txt").read_text()
    result = _parse_hydra_output(text, "10.10.10.5", "ssh")
    assert result.success is True
    assert len(result.credentials) == 2
    assert result.credentials[0].username == "root"
    assert result.credentials[0].password == "toor"


def test_parse_hydra_output_not_found():
    text = "0 of 1 target successfully completed, 0 valid passwords found"
    result = _parse_hydra_output(text, "10.10.10.5", "ssh")
    assert result.success is False
    assert result.credentials == []


@pytest.mark.asyncio
async def test_hydra_ainvoke_works_with_roe_guard(
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

    Note: ``_save_raw`` is imported into ``hydra``'s namespace via
    ``from autored.tools.nmap import _save_raw``, so the patch target must
    be ``autored.tools.hydra._save_raw`` to intercept the call from
    inside ``hydra_brute``.
    """
    # 1. Register a RoE for the test engagement.
    roe = load_roe(sandbox_roe_yaml)
    register_roe("hydra-int", roe)

    # 2. Mock run_subprocess to return the fixture stdout.
    hydra_text = (fixtures_dir / "hydra_output.txt").read_text()

    async def fake_run_subprocess(cmd, timeout=3600):
        return SubprocessResult(
            stdout=hydra_text,
            stderr="",
            returncode=0,
            duration_sec=0.4,
            command=" ".join(cmd),
        )

    monkeypatch.setattr("autored.tools.hydra.run_subprocess", fake_run_subprocess)

    # 3. Mock _save_raw to a no-op so the test doesn't touch disk.
    async def fake_save_raw(*args, **kwargs):
        return ""

    monkeypatch.setattr("autored.tools.hydra._save_raw", fake_save_raw)

    # 4. Call the tool via .ainvoke({...}).
    result = await hydra_brute.ainvoke(
        {
            "target": "10.10.10.5",
            "service": "ssh",
            "usernames_file": "/tmp/users.txt",
            "passwords_file": "/tmp/pass.txt",
            "engagement_id": "hydra-int",
        }
    )

    # 5. Assert the returned object is the right Pydantic model with the
    #    expected fields populated.
    assert isinstance(result, BruteResult)
    assert result.target == "10.10.10.5"
    assert result.service == "ssh"
    assert result.success is True
    assert len(result.credentials) == 2
    assert isinstance(result.credentials[0], BruteCredential)
    assert result.credentials[0].username == "root"
    assert result.credentials[0].password == "toor"
    assert result.credentials[1].username == "admin"
    assert result.credentials[1].password == "admin123"
