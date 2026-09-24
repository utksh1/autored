"""Integration tests for the Vuln Agent node (Phase 2, Task 9).

Verifies the three required scenarios from the brief:
1. ``test_vuln_node_produces_hypotheses`` — happy path: CVEMatcher +
   ExploitFinder + Chroma all return data, Sonnet generates 1 hypothesis,
   HypothesisCritic returns "sound" → loop converges after 1 iteration.
2. ``test_vuln_node_no_viable_hypotheses`` — fully-patched target: CVE
   matches empty, LLM returns ``{"hypotheses": []}`` → node still
   transitions phase to "exploit" (Exploit Agent handles the empty list).
3. ``test_vuln_node_self_critique_non_convergence`` — Review Focus:
   critic always returns "needs_revision" → self-critique loop runs the
   full 3 iterations and ships the best version despite non-convergence.

Implementation note: per Phase 1 R1, the Vuln Agent calls the LLM through
``router.call_with_fallback("synthesize_findings", prompt)`` (returns the
response ``.content`` as a str directly), NOT via ``model.ainvoke`` on a
model returned by ``get_model``. So the tests mock
``autored.agents.vuln.call_with_fallback`` to return the fixture JSON
string directly. The three subagents (CVEMatcher, ExploitFinder,
HypothesisCritic) are mocked via their module-level @tool references, and
``ChromaStore`` is mocked at the class level to return ``[]`` for
``query_similar_findings`` (no past findings).
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from autored.agents.vuln import vuln_node
from autored.config import load_roe
from autored.models.host import Host
from autored.models.service import Service
from autored.state import EngagementState
from autored.subagents.cvematcher import CveMatch, CVEMatcherOutput
from autored.subagents.exploitfinder import ExploitFinderOutput
from autored.subagents.hypothesiscritic import CritiqueOutput
from autored.tools.nvd import NvdCve
from autored.tools.searchsploit import ExploitEntry


@pytest.fixture
def shocker_state(sandbox_roe_yaml):
    """A pre-vuln engagement state for HTB Shocker (Apache 2.2.22 + OpenSSH)."""
    roe = load_roe(sandbox_roe_yaml)
    return EngagementState(
        engagement_id="test-shocker-001",
        target_scope=["10.10.10.56"],
        operator="test",
        rules_of_engagement=roe,
        hosts=[
            Host(
                ip="10.10.10.56",
                hostname="shocker.htb",
                discovered_by="nmap",
            )
        ],
        services=[
            Service(
                host_ip="10.10.10.56",
                port=80,
                protocol="tcp",
                service="http",
                product="Apache httpd",
                version="2.2.22",
            ),
            Service(
                host_ip="10.10.10.56",
                port=2222,
                protocol="tcp",
                service="ssh",
                product="OpenSSH",
                version="7.2p2",
            ),
        ],
    )


@pytest.mark.asyncio
async def test_vuln_node_produces_hypotheses(shocker_state, fixtures_dir):
    """Happy path: 1 CVE → 1 exploit → 1 hypothesis → critic says "sound" → 1 iteration."""
    fake_cve_output = CVEMatcherOutput(
        cve_matches=[
            CveMatch(
                service="http",
                host_ip="10.10.10.56",
                port=80,
                product="Apache httpd",
                version="2.2.22",
                cves=[
                    NvdCve(
                        cve_id="CVE-2014-6271",
                        description="Shellshock",
                        cvss_score=10.0,
                        severity="CRITICAL",
                    )
                ],
            )
        ]
    )

    fake_exploit_output = ExploitFinderOutput(
        query="Apache 2.2.22",
        exploits=[
            ExploitEntry(
                edb_id="34900",
                title="Apache Shellshock",
                type="remote",
                platform="linux",
            )
        ],
    )

    fake_critique_output = CritiqueOutput(
        critique=[
            {
                "rank": 1,
                "issues": [],
                "verdict": "sound",
                "verdict_reason": "all checks pass",
            }
        ]
    )

    # Mock LLM (Sonnet, via call_with_fallback) returns the fixture JSON.
    hypotheses_json = (fixtures_dir / "llm_responses" / "vuln_hypotheses_shocker.json").read_text()
    mock_call = AsyncMock(return_value=hypotheses_json)

    with (
        patch("autored.agents.vuln.call_with_fallback", mock_call),
        patch("autored.subagents.cvematcher.cvematcher_subagent") as mock_cve,
        patch("autored.subagents.exploitfinder.exploitfinder_subagent") as mock_exploit,
        patch("autored.subagents.hypothesiscritic.hypothesiscritic_subagent") as mock_critic,
        patch("autored.agents.vuln.ChromaStore") as mock_chroma_cls,
    ):
        mock_cve.ainvoke = AsyncMock(return_value=fake_cve_output)
        mock_exploit.ainvoke = AsyncMock(return_value=fake_exploit_output)
        mock_critic.ainvoke = AsyncMock(return_value=fake_critique_output)

        mock_chroma = MagicMock()
        mock_chroma.query_similar_findings = AsyncMock(return_value=[])
        mock_chroma_cls.return_value = mock_chroma

        # I1 (Phase 3 fix wave): vuln_node now accepts a RunnableConfig
        # for signature uniformity with exploit_node. Vuln doesn't
        # consume the bus, so an empty config is fine.
        result = await vuln_node(shocker_state, config={})

    assert "attack_hypotheses" in result
    assert len(result["attack_hypotheses"]) >= 1
    assert result["attack_hypotheses"][0].cve == "CVE-2014-6271"
    assert result["phase"] == "exploit"
    # Self-critique loop converges after 1 iteration (verdict was "sound").
    assert mock_critic.ainvoke.call_count == 1
    # iteration_count is incremented by 1 (one vuln-node pass).
    assert result["iteration_count"] == shocker_state.iteration_count + 1


@pytest.mark.asyncio
async def test_vuln_node_no_viable_hypotheses(shocker_state):
    """Review Focus: fully-patched target — Vuln Agent returns empty hypotheses,
    explains why, and still transitions phase to "exploit" (Exploit Agent
    handles the empty list downstream rather than the engagement stalling)."""
    fake_cve_output = CVEMatcherOutput(cve_matches=[])
    fake_exploit_output = ExploitFinderOutput(query="test", exploits=[])
    fake_critique_output = CritiqueOutput(critique=[])

    # LLM returns empty hypotheses.
    mock_call = AsyncMock(return_value='{"hypotheses": []}')

    with (
        patch("autored.agents.vuln.call_with_fallback", mock_call),
        patch("autored.subagents.cvematcher.cvematcher_subagent") as mock_cve,
        patch("autored.subagents.exploitfinder.exploitfinder_subagent") as mock_exploit,
        patch("autored.subagents.hypothesiscritic.hypothesiscritic_subagent") as mock_critic,
        patch("autored.agents.vuln.ChromaStore") as mock_chroma_cls,
    ):
        mock_cve.ainvoke = AsyncMock(return_value=fake_cve_output)
        mock_exploit.ainvoke = AsyncMock(return_value=fake_exploit_output)
        mock_critic.ainvoke = AsyncMock(return_value=fake_critique_output)

        mock_chroma = MagicMock()
        mock_chroma.query_similar_findings = AsyncMock(return_value=[])
        mock_chroma_cls.return_value = mock_chroma

        # I1 (Phase 3 fix wave): uniform node signatures.
        result = await vuln_node(shocker_state, config={})

    assert result["attack_hypotheses"] == []
    # Still transitions — Exploit Agent handles empty hypotheses downstream.
    assert result["phase"] == "exploit"
    # Critic must NOT be invoked (loop short-circuits on empty hypotheses).
    assert mock_critic.ainvoke.call_count == 0


@pytest.mark.asyncio
async def test_vuln_node_self_critique_non_convergence(shocker_state, fixtures_dir):
    """Review Focus: self-critique loop runs max 3 iterations on persistent
    disagreement, then ships the best version anyway. The for...else clause
    logs non-convergence but does NOT block — phase transitions to "exploit"
    with the last-revised hypothesis list rather than stalling the engagement.
    """
    fake_cve_output = CVEMatcherOutput(
        cve_matches=[
            CveMatch(
                service="http",
                host_ip="10.10.10.56",
                port=80,
                product="Apache",
                version="2.2.22",
                cves=[
                    NvdCve(
                        cve_id="CVE-2014-6271",
                        description="Shellshock",
                    )
                ],
            )
        ]
    )
    fake_exploit_output = ExploitFinderOutput(query="x", exploits=[])
    # Critic always says "needs_revision" — never converges.
    fake_critique_output = CritiqueOutput(
        critique=[
            {
                "rank": 1,
                "issues": ["perpetual disagreement"],
                "verdict": "needs_revision",
                "verdict_reason": "test",
            }
        ]
    )

    hypotheses_json = (fixtures_dir / "llm_responses" / "vuln_hypotheses_shocker.json").read_text()
    mock_call = AsyncMock(return_value=hypotheses_json)

    with (
        patch("autored.agents.vuln.call_with_fallback", mock_call),
        patch("autored.subagents.cvematcher.cvematcher_subagent") as mock_cve,
        patch("autored.subagents.exploitfinder.exploitfinder_subagent") as mock_exploit,
        patch("autored.subagents.hypothesiscritic.hypothesiscritic_subagent") as mock_critic,
        patch("autored.agents.vuln.ChromaStore") as mock_chroma_cls,
    ):
        mock_cve.ainvoke = AsyncMock(return_value=fake_cve_output)
        mock_exploit.ainvoke = AsyncMock(return_value=fake_exploit_output)
        mock_critic.ainvoke = AsyncMock(return_value=fake_critique_output)

        mock_chroma = MagicMock()
        mock_chroma.query_similar_findings = AsyncMock(return_value=[])
        mock_chroma_cls.return_value = mock_chroma

        # I1 (Phase 3 fix wave): uniform node signatures.
        result = await vuln_node(shocker_state, config={})

    # Critic called exactly 3 times (max iterations), then ships best version.
    assert mock_critic.ainvoke.call_count == 3
    # Ships despite non-convergence — phase still transitions.
    assert result["phase"] == "exploit"
    assert len(result["attack_hypotheses"]) >= 1
