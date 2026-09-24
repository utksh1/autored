"""Unit tests for tunnel tools (Phase 5 Task 4).

The brief-mandated tests cover the build/config helpers + the
``TunnelResult`` model. Two integration tests at the bottom drive the
decorated wrappers end-to-end via ``.ainvoke()`` with ``_save_raw``
mocked (no live ligolo / chisel binary required), enforcing the
``@tool`` OUTER + ``@roe_guard`` INNER decorator order (Ruling 1) and
confirming the recorded ``TunnelConfig.teardown_command`` is the
verbatim string the Cleanup Agent will run.
"""
from __future__ import annotations

import pytest

from autored.config import load_roe
from autored.roe_guard import register_roe
from autored.tools.tunnel import (
    TunnelResult,
    _autored_lhost,
    _build_chisel_cmd,
    _build_ligolo_cmd,
    _config_from_chisel,
    _config_from_ligolo,
    chisel_reverse,
    ligolo_connect,
)


def test_build_ligolo_cmd():
    cmd = _build_ligolo_cmd("10.10.14.5", 11601)
    assert cmd[0] == "ligolo-ng"
    assert "--connect" in cmd
    assert "10.10.14.5:11601" in cmd


def test_build_chisel_cmd():
    cmd = _build_chisel_cmd("10.10.14.5", 1080)
    assert cmd[:2] == ["chisel", "client"]
    assert "10.10.14.5:1080" in cmd
    assert "R:socks" in cmd  # reverse SOCKS pivot


def test_ligolo_config_records_teardown():
    cfg = _config_from_ligolo("10.10.14.5", 11601)
    assert cfg.tool == "ligolo"
    assert cfg.proxy_endpoint == "10.10.14.5:11601"
    assert cfg.local_port == 11601
    assert cfg.teardown_command == "pkill -f ligolo-ng"


def test_chisel_config_records_teardown():
    cfg = _config_from_chisel("10.10.14.5", 1080, "192.168.56.0/24")
    assert cfg.tool == "chisel"
    assert cfg.target_network == "192.168.56.0/24"
    assert "10.10.14.5:1080" in cfg.teardown_command
    assert cfg.teardown_command.startswith("pkill -f")


def test_tunnel_result_model():
    cfg = _config_from_ligolo("10.10.14.5", 11601)
    r = TunnelResult(command_built="ligolo-ng --connect x", tunnel_config=cfg)
    assert r.success is True
    assert r.raw_output_path == ""


def test_autored_lhost_reads_env(monkeypatch):
    """``_autored_lhost`` falls back to 127.0.0.1 when ``AUTORED_LHOST``
    is unset; honours the env var when it is set (used by
    ``chisel_reverse``'s default)."""
    monkeypatch.delenv("AUTORED_LHOST", raising=False)
    assert _autored_lhost() == "127.0.0.1"
    monkeypatch.setenv("AUTORED_LHOST", "10.10.14.5")
    assert _autored_lhost() == "10.10.14.5"


@pytest.mark.asyncio
async def test_ligolo_connect_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, monkeypatch
):
    """Integration test: ``@tool`` outer + ``@roe_guard`` inner per Ruling 1.

    The sandbox RoE has ``allowed_ips: ["0.0.0.0/0"]`` so the
    ``proxy_ip`` scope check (added in Task 1) passes for the
    tunnel endpoint. The teardown command is the verbatim string
    the Cleanup Agent will run.
    """
    roe = load_roe(sandbox_roe_yaml)
    register_roe("ligolo-int", roe)

    async def fake_save_raw(*args, **kwargs):
        return "/tmp/fake/ligolo.out"

    monkeypatch.setattr("autored.tools.tunnel._save_raw", fake_save_raw)

    result = await ligolo_connect.ainvoke(
        {
            "proxy_ip": "10.10.14.5",
            "proxy_port": 11601,
            "engagement_id": "ligolo-int",
        }
    )

    assert isinstance(result, TunnelResult)
    assert result.success is True
    assert result.tunnel_config.tool == "ligolo"
    assert result.tunnel_config.proxy_endpoint == "10.10.14.5:11601"
    assert result.tunnel_config.teardown_command == "pkill -f ligolo-ng"
    assert result.raw_output_path == "/tmp/fake/ligolo.out"


@pytest.mark.asyncio
async def test_chisel_reverse_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, monkeypatch
):
    """Integration test for ``chisel_reverse`` — same rationale as ligolo.

    Confirms the ``lhost`` kwarg overrides the ``AUTORED_LHOST`` env
    var, and that the recorded teardown command is parameterised by
    the chosen endpoint so the Cleanup Agent kills the right process.
    """
    roe = load_roe(sandbox_roe_yaml)
    register_roe("chisel-int", roe)

    async def fake_save_raw(*args, **kwargs):
        return "/tmp/fake/chisel.out"

    monkeypatch.setattr("autored.tools.tunnel._save_raw", fake_save_raw)

    result = await chisel_reverse.ainvoke(
        {
            "lhost": "10.10.14.5",
            "lport": 1080,
            "target_network": "192.168.56.0/24",
            "engagement_id": "chisel-int",
        }
    )

    assert isinstance(result, TunnelResult)
    assert result.success is True
    assert result.tunnel_config.tool == "chisel"
    assert result.tunnel_config.target_network == "192.168.56.0/24"
    assert result.tunnel_config.teardown_command == (
        "pkill -f 'chisel client 10.10.14.5:1080'"
    )
    assert result.raw_output_path == "/tmp/fake/chisel.out"
