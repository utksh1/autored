"""Integration test for the Recon Agent (Phase 1, Task 22).

Verifies that ``recon_node`` — the Phase 1 LangGraph recon node —
correctly:
  1. Calls ``get_model("plan_recon").ainvoke(prompt)`` to get a JSON plan.
  2. Parses the plan into ``{"steps": [...]}`` (handling markdown fences).
  3. Dispatches each step to the right sub-agent via ``.ainvoke({...})``,
     respecting ``depends_on`` (parallel batches by dependency level).
  4. Merges sub-agent outputs into state-shaped dict (``hosts``,
     ``services``, ``web_apps``, ``subdomains``, ``directories``).

The LLM and the three sub-agents referenced in the fixture plan
(``portscan``, ``webenum``, ``dnsenum``) are all mocked. The two unused
sub-agents (``subdomainenum``, ``vhostenum``) aren't called by this
plan, so they aren't patched.
"""
from unittest.mock import AsyncMock, patch

import pytest

from autored.agents.recon import recon_node
from autored.config import load_roe
from autored.state import EngagementState
from autored.subagents.dnsenum import DnsResult
from autored.subagents.portscan import PortScanOutput
from autored.subagents.webenum import WebEnumOutput
from autored.tools.nmap import NmapHost, NmapPort, NmapResult


@pytest.fixture
def test_state(sandbox_roe_yaml):
    """Build an EngagementState against the sandbox RoE."""
    roe = load_roe(sandbox_roe_yaml)
    return EngagementState(
        engagement_id="test-eng-001",
        target_scope=["10.10.10.5"],
        operator="test",
        rules_of_engagement=roe,
    )


@pytest.mark.asyncio
async def test_recon_node_executes_plan(test_state, fixtures_dir):
    # Mock LLM to return our fixture plan
    plan_json = (fixtures_dir / "llm_responses" / "recon_plan_lame.json").read_text()

    # Mock sub-agent outputs
    fake_portscan = PortScanOutput(
        target="10.10.10.5",
        deep_scan=NmapResult(
            target="10.10.10.5", scan_type="service",
            hosts=[NmapHost(ip="10.10.10.5", hostname="lame.htb", ports=[
                NmapPort(port=21, protocol="tcp", state="open", service="ftp"),
                NmapPort(port=22, protocol="tcp", state="open", service="ssh"),
            ])],
        ),
    )
    fake_webenum = WebEnumOutput(url="http://10.10.10.5")
    fake_dnsenum = DnsResult(hostname="lame.htb", records=[])

    # ``recon_node`` calls ``call_with_fallback("plan_recon", prompt)``
    # (spec §4.3 — centralised refusal detection + DeepSeek fallback).
    # ``call_with_fallback`` returns the response text (a ``str``),
    # not a message object, so the mock returns ``plan_json`` directly.
    with patch("autored.agents.recon.call_with_fallback",
               new=AsyncMock(return_value=plan_json)), \
         patch("autored.subagents.portscan.portscan_subagent") as mock_portscan, \
         patch("autored.subagents.webenum.webenum_subagent") as mock_webenum, \
         patch("autored.subagents.dnsenum.dnsenum_subagent") as mock_dnsenum:

        mock_portscan.ainvoke = AsyncMock(return_value=fake_portscan)
        mock_webenum.ainvoke = AsyncMock(return_value=fake_webenum)
        mock_dnsenum.ainvoke = AsyncMock(return_value=fake_dnsenum)

        # I1 (Phase 3 fix wave): recon_node now accepts a RunnableConfig
        # for signature uniformity with exploit_node. Recon itself
        # doesn't consume the bus, so an empty config is fine.
        result = await recon_node(test_state, config={})

    # Verify state was updated
    assert "hosts" in result
    assert len(result["hosts"]) == 1
    assert result["hosts"][0].ip == "10.10.10.5"
    assert "services" in result
    assert len(result["services"]) == 2  # ftp + ssh
    assert result["phase"] == "vuln"
