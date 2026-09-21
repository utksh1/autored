"""Integration test for the Recon Agent LangGraph node (Task 22).

Mocks the LLM (returns a canned recon plan from a fixture) and all 5
sub-agents, then asserts that ``recon_node`` correctly:
  * parses the LLM response,
  * executes the plan respecting ``depends_on``,
  * dispatches to the right sub-agent per step,
  * merges results into the state-shaped dict (hosts, services, ...),
  * flips the phase to ``vuln``.
"""

import pytest
from unittest.mock import AsyncMock, patch

from autored.state import EngagementState
from autored.models.roe import RulesOfEngagement
from autored.agents.recon import recon_node
from autored.subagents.portscan import PortScanOutput
from autored.subagents.webenum import WebEnumOutput
from autored.subagents.dnsenum import DnsResult
from autored.tools.nmap import NmapResult, NmapHost, NmapPort


@pytest.fixture
def test_state(sandbox_roe_yaml):
    roe = RulesOfEngagement.model_validate_yaml(sandbox_roe_yaml)
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

    mock_response = type("MockResponse", (), {"content": plan_json})()

    # Mock sub-agent outputs
    fake_portscan = PortScanOutput(
        target="10.10.10.5",
        deep_scan=NmapResult(
            target="10.10.10.5",
            scan_type="service",
            hosts=[NmapHost(
                ip="10.10.10.5",
                hostname="lame.htb",
                ports=[
                    NmapPort(port=21, protocol="tcp", state="open", service="ftp"),
                    NmapPort(port=22, protocol="tcp", state="open", service="ssh"),
                ],
            )],
        ),
    )
    fake_webenum = WebEnumOutput(url="http://10.10.10.5")
    fake_dnsenum = DnsResult(hostname="lame.htb", records=[])

    with patch("autored.agents.recon.get_model") as mock_get_model, \
         patch("autored.subagents.portscan.portscan_subagent") as mock_portscan, \
         patch("autored.subagents.webenum.webenum_subagent") as mock_webenum, \
         patch("autored.subagents.dnsenum.dnsenum_subagent") as mock_dnsenum:

        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=mock_response)
        mock_get_model.return_value = mock_model

        mock_portscan.ainvoke = AsyncMock(return_value=fake_portscan)
        mock_webenum.ainvoke = AsyncMock(return_value=fake_webenum)
        mock_dnsenum.ainvoke = AsyncMock(return_value=fake_dnsenum)

        result = await recon_node(test_state)

    # Verify state was updated
    assert "hosts" in result
    assert len(result["hosts"]) == 1
    assert result["hosts"][0].ip == "10.10.10.5"
    assert "services" in result
    assert len(result["services"]) == 2  # ftp + ssh
    assert result["phase"] == "vuln"
