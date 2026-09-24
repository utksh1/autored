"""Unit tests for TechReportWriter (Phase 6 Task 5)."""
import json
from unittest.mock import AsyncMock, MagicMock, patch

from autored.models import Secret
from autored.models.roe import RulesOfEngagement
from autored.state import EngagementState
from autored.subagents.techreportwriter import (
    _redact_secret,
    _redacted_state_dict,
    _template_tech_report,
    techreportwriter_subagent,
)

PLAINTEXT = "SuperSecret123!"
NTLM = "31d6cfe0d16ae931b73c59d7e0c089c0"


def _roe() -> RulesOfEngagement:
    return RulesOfEngagement(
        engagement_name="t", operator="t", operator_signature="t",
        allowed_ips=["*"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, data_destruction_allowed=False,
        kernel_exploits_allowed=True, hitl_mode="auto_approve",
    )


def _state_with_secrets() -> EngagementState:
    state = EngagementState(
        engagement_id="e1", target_scope=["10.0.0.5"],
        operator="t", rules_of_engagement=_roe(),
    )
    state.harvested_secrets = [
        Secret(host_ip="10.0.0.5", secret_type="password",
               secret_value=PLAINTEXT, source="mimikatz:wdigest/administrator"),
        Secret(host_ip="10.0.0.5", secret_type="hash",
               secret_value=NTLM, source="mimikatz:kerberos/administrator"),
    ]
    return state


def test_redact_secret_hides_value_keeps_fingerprint():
    redacted = _redact_secret(PLAINTEXT)
    assert PLAINTEXT not in redacted
    assert redacted.startswith("***REDACTED***")
    assert "sha256:" in redacted
    assert len(redacted.split("sha256:")[1].rstrip(")")) == 8


def test_redact_secret_is_deterministic():
    """Same input → same fingerprint (correlates with memory writer Task 8)."""
    assert _redact_secret("x") == _redact_secret("x")


def test_redacted_state_dict_never_contains_secret_values():
    """Review Focus #2 — secret material must not survive redaction."""
    redacted = _redacted_state_dict(_state_with_secrets())
    dumped = json.dumps(redacted)
    assert PLAINTEXT not in dumped
    assert NTLM not in dumped
    assert dumped.count("***REDACTED***") == 2
    # usernames / hosts survive — they are report material
    assert "administrator" in dumped


def test_template_contains_all_sections():
    data = {
        "summary": {"target": "10.0.0.5", "engagement_id": "e1", "outcome": "ok",
                    "cleanup_all_verified": True},
        "state": _redacted_state_dict(_state_with_secrets()),
    }
    md = _template_tech_report(data)
    for section in (
        "## Scope", "## Findings", "## Footholds", "## Privilege Escalation",
        "## Persistence Artifacts", "## Defense Evasion", "## Exfiltration",
        "## Lateral Movement", "## Cleanup", "## Evidence Inventory", "## Errors",
    ):
        assert section in md, f"missing section {section}"
    assert PLAINTEXT not in md  # redaction flows through the template too


async def test_llm_narrative_plus_deterministic_sections():
    mock_response = MagicMock()
    mock_response.content = "## Attack Narrative\n\nRecon found SMB; EternalBlue gave SYSTEM."
    with patch("autored.subagents.techreportwriter.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=mock_response)
        mock_get_model.return_value = mock_model

        data = {
            "summary": {"target": "10.0.0.5", "engagement_id": "e1", "outcome": "ok",
                        "cleanup_all_verified": True},
            "state": _redacted_state_dict(_state_with_secrets()),
        }
        output = await techreportwriter_subagent.ainvoke({
            "engagement_data": json.dumps(data), "engagement_id": "e1",
        })
    assert "## Attack Narrative" in output.report_markdown
    assert "## Findings" in output.report_markdown  # deterministic sections appended
    assert output.used_fallback is False
    assert PLAINTEXT not in output.report_markdown


async def test_llm_failure_falls_back():
    with patch("autored.subagents.techreportwriter.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(side_effect=RuntimeError("timeout"))
        mock_get_model.return_value = mock_model

        data = {
            "summary": {"target": "10.0.0.5", "engagement_id": "e1", "outcome": "ok",
                        "cleanup_all_verified": True},
            "state": _redacted_state_dict(_state_with_secrets()),
        }
        output = await techreportwriter_subagent.ainvoke({
            "engagement_data": json.dumps(data), "engagement_id": "e1",
        })
    assert output.used_fallback is True
    assert "## Findings" in output.report_markdown
    assert PLAINTEXT not in output.report_markdown


async def test_llm_refusal_falls_back():
    """Review Focus #3 — refusal must trigger fallback, never lose the report."""
    mock_response = MagicMock()
    mock_response.content = "I cannot assist with this request."
    with patch("autored.subagents.techreportwriter.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=mock_response)
        mock_get_model.return_value = mock_model

        data = {
            "summary": {"target": "10.0.0.5", "engagement_id": "e1", "outcome": "ok",
                        "cleanup_all_verified": True},
            "state": _redacted_state_dict(_state_with_secrets()),
        }
        output = await techreportwriter_subagent.ainvoke({
            "engagement_data": json.dumps(data), "engagement_id": "e1",
        })
    assert output.used_fallback is True
    assert "## Findings" in output.report_markdown


async def test_empty_llm_response_falls_back():
    mock_response = MagicMock()
    mock_response.content = ""
    with patch("autored.subagents.techreportwriter.get_model") as mock_get_model:
        mock_model = AsyncMock()
        mock_model.ainvoke = AsyncMock(return_value=mock_response)
        mock_get_model.return_value = mock_model

        data = {
            "summary": {"target": "10.0.0.5", "engagement_id": "e1", "outcome": "ok",
                        "cleanup_all_verified": True},
            "state": _redacted_state_dict(_state_with_secrets()),
        }
        output = await techreportwriter_subagent.ainvoke({
            "engagement_data": json.dumps(data), "engagement_id": "e1",
        })
    assert output.used_fallback is True
    assert "## Attack Narrative" in output.report_markdown  # placeholder narrative
    assert "## Findings" in output.report_markdown
