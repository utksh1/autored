"""Tests for the gobuster vhost tool wrapper (Phase 1, Task 15).

The fixture file is plain text (``gobuster_vhost_lame.txt``) matching
what the real ``gobuster vhost`` binary emits with ``-q`` (quiet mode).
"""
import pytest

from autored.config import load_roe
from autored.roe_guard import register_roe
from autored.subprocess_runner import SubprocessResult
from autored.tools.gobuster_vhost import (
    VhostEntry,
    VhostList,
    _build_gobuster_cmd,
    _parse_gobuster_output,
    gobuster_vhost,
)


def test_parse_gobuster_output(fixtures_dir):
    text = (fixtures_dir / "gobuster_vhost_lame.txt").read_text()
    result = _parse_gobuster_output(text, "lame.htb")
    assert isinstance(result, VhostList)
    assert result.domain == "lame.htb"
    assert len(result.vhosts) == 2
    assert result.vhosts[0].hostname == "dev.lame.htb"
    assert result.vhosts[0].status_code == 200


def test_parse_gobuster_empty():
    result = _parse_gobuster_output("", "example.com")
    assert result.vhosts == []


def test_build_gobuster_cmd():
    cmd = _build_gobuster_cmd("http://lame.htb", "/usr/share/wordlists/dirb/common.txt")
    assert "gobuster" in cmd[0]
    assert "vhost" in cmd
    assert "-u" in cmd
    assert "http://lame.htb" in cmd
    assert "-w" in cmd


@pytest.mark.asyncio
async def test_gobuster_vhost_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, fixtures_dir, monkeypatch
):
    """Integration test: call the decorated tool end-to-end via .ainvoke().

    Regression catcher for the decorator-stacking bug (C1+C2 from Batch A
    review): the brief's spec'd ``@roe_guard`` over ``@tool`` order produced
    a StructuredTool that was not callable via ``.ainvoke({...})``. With the
    swapped order (``@tool`` outermost, ``@roe_guard`` inner), the
    StructuredTool's underlying coroutine is a regular async def, and
    ``.ainvoke({...})`` dispatches correctly through the RoE wrapper.

    Note: ``_save_raw`` is imported into ``gobuster_vhost``'s namespace via
    ``from autored.tools.nmap import _save_raw``, so the patch target must
    be ``autored.tools.gobuster_vhost._save_raw`` (not
    ``autored.tools.nmap._save_raw``) to intercept the call from inside
    ``gobuster_vhost``.
    """
    # 1. Register a RoE for the test engagement.
    roe = load_roe(sandbox_roe_yaml)
    register_roe("gobuster-vhost-int", roe)

    # 2. Mock run_subprocess to return the fixture text as stdout.
    gobuster_text = (fixtures_dir / "gobuster_vhost_lame.txt").read_text()

    async def fake_run_subprocess(cmd, timeout=300):
        return SubprocessResult(
            stdout=gobuster_text,
            stderr="",
            returncode=0,
            duration_sec=0.3,
            command=" ".join(cmd),
        )

    monkeypatch.setattr(
        "autored.tools.gobuster_vhost.run_subprocess", fake_run_subprocess
    )

    # 3. Mock _save_raw to a no-op so the test doesn't touch disk. The patch
    #    target is gobuster_vhost's namespace because ``from x import y``
    #    copies the reference at import time — patching the source module's
    #    attribute wouldn't affect the local binding.
    async def fake_save_raw(*args, **kwargs):
        return ""

    monkeypatch.setattr("autored.tools.gobuster_vhost._save_raw", fake_save_raw)

    # 4. Call the tool via .ainvoke({...}).
    result = await gobuster_vhost.ainvoke(
        {
            "url": "http://lame.htb",
            "wordlist": "/usr/share/wordlists/dirb/common.txt",
            "engagement_id": "gobuster-vhost-int",
        }
    )

    # 5. Assert the returned object is the right Pydantic model with the
    #    expected fields populated.
    assert isinstance(result, VhostList)
    assert result.domain == "lame.htb"
    assert len(result.vhosts) == 2
    assert isinstance(result.vhosts[0], VhostEntry)
    assert result.vhosts[0].hostname == "dev.lame.htb"
    assert result.vhosts[0].status_code == 200
    assert result.vhosts[0].content_length == 1234
    assert result.vhosts[1].hostname == "admin.lame.htb"
    assert result.vhosts[1].status_code == 401
    assert result.vhosts[1].content_length == 567
