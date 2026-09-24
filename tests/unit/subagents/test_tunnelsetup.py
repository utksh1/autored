"""Unit tests for the TunnelSetup sub-agent (Phase 5 Task 7)."""
from unittest.mock import AsyncMock, patch

from autored.subagents.tunnelsetup import tunnelsetup_subagent
from autored.tools.tunnel import TunnelResult, _config_from_chisel


async def test_tunnelsetup_returns_config():
    cfg = _config_from_chisel("10.10.14.5", 1080, "0.0.0.0/0")
    result = TunnelResult(
        command_built="chisel client 10.10.14.5:1080 R:socks",
        tunnel_config=cfg, success=True, raw_output_path="",
    )
    with patch("autored.subagents.tunnelsetup.chisel_reverse") as mock_chisel:
        mock_chisel.ainvoke = AsyncMock(return_value=result)
        out = await tunnelsetup_subagent.ainvoke({
            "pivot": {"target_host": "192.168.56.11", "method": "wmiexec",
                      "needs_tunnel": True},
            "engagement_id": "e1",
        })
    assert out.tunnel is not None
    assert out.tunnel.tool == "chisel"
    assert out.tunnel.teardown_command.startswith("pkill")
    # lhost is left empty so the tool resolves AUTORED_LHOST itself
    chisel_args = mock_chisel.ainvoke.call_args.kwargs
    assert chisel_args["lhost"] == ""
    assert chisel_args["lport"] == 1080


async def test_tunnelsetup_handles_tool_failure():
    with patch("autored.subagents.tunnelsetup.chisel_reverse") as mock_chisel:
        mock_chisel.ainvoke = AsyncMock(side_effect=RuntimeError("no chisel binary"))
        out = await tunnelsetup_subagent.ainvoke({
            "pivot": {"target_host": "192.168.56.11", "method": "wmiexec",
                      "needs_tunnel": True},
            "engagement_id": "e1",
        })
    assert out.tunnel is None  # tunnel failure must not kill the pivot
