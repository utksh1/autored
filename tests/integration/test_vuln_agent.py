"""Integration tests for the Vuln Agent node (Phase 2, Task 9).

These tests cover the three scenarios the Vuln Agent must handle:
  1. Happy path — Shocker/Shellshock target produces ranked attack
     hypotheses, the self-critique loop converges in one iteration.
  2. **Review Focus** — fully patched target → CVEMatcher and
     ExploitFinder both return empty, LLM emits `{"hypotheses": []}`,
     the loop short-circuits on empty hypotheses, the agent still
     transitions to ``phase="exploit"`` so the Exploit Agent can
     handle the "no viable path" case.
  3. **Review Focus** — the HypothesisCritic never says "sound";
     the loop runs the maximum 3 iterations and the best (last) version
     is still shipped.

Mocks: LLM (``get_model``), all three sub-agents
(``cvematcher_subagent``, ``exploitfinder_subagent``,
``hypothesiscritic_subagent``), and ``ChromaStore``.
"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from autored.state import EngagementState
from autored.models.roe import RulesOfEngagement
from autored.models.service import Service
from autored.models.host import Host
from autored.agents.vuln import vuln_node
from autored.tools.nvd import NvdCve


@pytest.fixture
def shocker_state(sandbox_roe_yaml):
    roe = RulesOfEngagement.model_validate_yaml(sandbox_roe_yaml)
    return EngagementState(
        engagement_id="test-shocker-001",
        target_scope=["10.10.10.56"],
        operator="test",
        rules_of_engagement=roe,
        hosts=[Host(ip="10.10.10.56", hostname="shocker.htb", discovered_by="nmap")],
        services=[
            Service(host_ip="10.10.10.56", port=80, protocol="tcp",
                    service="http", product="Apache httpd", version="2.2.22"),
            Service(host_ip="10.10.10.56", port=2222, protocol="tcp",
                    service="ssh", product="OpenSSH", version="7.2p2"),
        ],
    )


@pytest.mark.asyncio
async def test_vuln_node_produces_hypotheses(shocker_state, fixtures_dir):
    # Mock CVEMatcher to return Shellshock CVE
    from autored.subagents.cvematcher import CVEMatcherOutput, CveMatch
    fake_cve_output = CVEMatcherOutput(cve_matches=[
        CveMatch(
            service="http", host_ip="10.10.10.56", port=80,
            product="Apache httpd", version="2.2.22",
            cves=[NvdCve(cve_id="CVE-2014-6271", description="Shellshock", cvss_score=10.0, severity="CRITICAL")],
        ),
    ])

    # Mock ExploitFinder to return Shellshock exploit
    from autored.subagents.exploitfinder import ExploitFinderOutput
    from autored.tools.searchsploit import ExploitEntry
    fake_exploit_output = ExploitFinderOutput(
        query="Apache 2.2.22",
        exploits=[ExploitEntry(edb_id="34900", title="Apache Shellshock", type="remote", platform="linux")],
    )

    # Mock HypothesisCritic to return "sound" verdict
    from autored.subagents.hypothesiscritic import CritiqueOutput
    fake_critique_output = CritiqueOutput(critique=[
        {"rank": 1, "issues": [], "verdict": "sound", "verdict_reason": "all checks pass"},
    ])

    # Mock LLM (Sonnet) to return hypothesis JSON
    hypotheses_json = (fixtures_dir / "llm_responses" / "vuln_hypotheses_shocker.json").read_text()
    mock_response = MagicMock()
    mock_response.content = hypotheses_json

    with patch("autored.agents.vuln.get_model") as mock_get_model, \
         patch("autored.subagents.cvematcher.cvematcher_subagent") as mock_cve, \
         patch("autored.subagents.exploitfinder.exploitfinder_subagent") as mock_exploit, \
         patch("autored.subagents.hypothesiscritic.hypothesiscritic_subagent") as mock_critic, \
         patch("autored.agents.vuln.ChromaStore") as mock_chroma_cls:

        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=mock_response)
        mock_get_model.return_value = mock_model

        mock_cve.ainvoke = AsyncMock(return_value=fake_cve_output)
        mock_exploit.ainvoke = AsyncMock(return_value=fake_exploit_output)
        mock_critic.ainvoke = AsyncMock(return_value=fake_critique_output)

        mock_chroma = MagicMock()
        mock_chroma.query_similar_findings = AsyncMock(return_value=[])
        mock_chroma_cls.return_value = mock_chroma

        result = await vuln_node(shocker_state)

    assert "attack_hypotheses" in result
    assert len(result["attack_hypotheses"]) >= 1
    assert result["attack_hypotheses"][0].cve == "CVE-2014-6271"
    assert result["phase"] == "exploit"
    # Self-critique loop should have run (1 iteration since verdict was "sound")
    assert mock_critic.ainvoke.call_count == 1


@pytest.mark.asyncio
async def test_vuln_node_no_viable_hypotheses(shocker_state):
    """Review Focus: fully patched target — Vuln Agent returns empty hypotheses, explains why."""
    # No CVEs found
    from autored.subagents.cvematcher import CVEMatcherOutput
    fake_cve_output = CVEMatcherOutput(cve_matches=[])
    from autored.subagents.exploitfinder import ExploitFinderOutput
    fake_exploit_output = ExploitFinderOutput(query="test", exploits=[])
    from autored.subagents.hypothesiscritic import CritiqueOutput
    fake_critique_output = CritiqueOutput(critique=[])

    # LLM returns empty hypotheses
    mock_response = MagicMock()
    mock_response.content = '{"hypotheses": []}'

    with patch("autored.agents.vuln.get_model") as mock_get_model, \
         patch("autored.subagents.cvematcher.cvematcher_subagent") as mock_cve, \
         patch("autored.subagents.exploitfinder.exploitfinder_subagent") as mock_exploit, \
         patch("autored.subagents.hypothesiscritic.hypothesiscritic_subagent") as mock_critic, \
         patch("autored.agents.vuln.ChromaStore") as mock_chroma_cls:

        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=mock_response)
        mock_get_model.return_value = mock_model
        mock_cve.ainvoke = AsyncMock(return_value=fake_cve_output)
        mock_exploit.ainvoke = AsyncMock(return_value=fake_exploit_output)
        mock_critic.ainvoke = AsyncMock(return_value=fake_critique_output)
        mock_chroma = MagicMock()
        mock_chroma.query_similar_findings = AsyncMock(return_value=[])
        mock_chroma_cls.return_value = mock_chroma

        result = await vuln_node(shocker_state)

    assert result["attack_hypotheses"] == []
    assert result["phase"] == "exploit"  # still transitions — Exploit Agent handles empty hypotheses


@pytest.mark.asyncio
async def test_vuln_node_self_critique_non_convergence(shocker_state, fixtures_dir):
    """Review Focus: self-critique loop runs max 3 iterations on persistent disagreement."""
    from autored.subagents.cvematcher import CVEMatcherOutput, CveMatch
    fake_cve_output = CVEMatcherOutput(cve_matches=[
        CveMatch(service="http", host_ip="10.10.10.56", port=80,
                 product="Apache", version="2.2.22",
                 cves=[NvdCve(cve_id="CVE-2014-6271", description="Shellshock")]),
    ])
    from autored.subagents.exploitfinder import ExploitFinderOutput
    fake_exploit_output = ExploitFinderOutput(query="x", exploits=[])
    from autored.subagents.hypothesiscritic import CritiqueOutput
    # Critic always says "needs_revision" — never converges
    fake_critique_output = CritiqueOutput(critique=[
        {"rank": 1, "issues": ["perpetual disagreement"], "verdict": "needs_revision", "verdict_reason": "test"},
    ])

    hypotheses_json = (fixtures_dir / "llm_responses" / "vuln_hypotheses_shocker.json").read_text()
    mock_response = MagicMock()
    mock_response.content = hypotheses_json

    with patch("autored.agents.vuln.get_model") as mock_get_model, \
         patch("autored.subagents.cvematcher.cvematcher_subagent") as mock_cve, \
         patch("autored.subagents.exploitfinder.exploitfinder_subagent") as mock_exploit, \
         patch("autored.subagents.hypothesiscritic.hypothesiscritic_subagent") as mock_critic, \
         patch("autored.agents.vuln.ChromaStore") as mock_chroma_cls:

        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=mock_response)
        mock_get_model.return_value = mock_model
        mock_cve.ainvoke = AsyncMock(return_value=fake_cve_output)
        mock_exploit.ainvoke = AsyncMock(return_value=fake_exploit_output)
        mock_critic.ainvoke = AsyncMock(return_value=fake_critique_output)
        mock_chroma = MagicMock()
        mock_chroma.query_similar_findings = AsyncMock(return_value=[])
        mock_chroma_cls.return_value = mock_chroma

        result = await vuln_node(shocker_state)

    # Should run critique loop 3 times (max), then ship best version
    assert mock_critic.ainvoke.call_count == 3
    assert len(result["attack_hypotheses"]) >= 1  # ships despite non-convergence
