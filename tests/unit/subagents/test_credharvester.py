"""Tests for the CredHarvester sub-agent (Phase 4, Task 8).

Verifies that ``credharvester_subagent`` dispatches to ``mimikatz_wrapper``
on Windows footholds and converts each harvested NTLM hash / plaintext
password into its own ``Secret`` record. The Phase 4 stub defers
``secretsdump`` (Linux) and ``certipy`` (AD) credential-chaining to Phase 5.

Also verifies the ``os_type`` dispatch: unknown OS values log a warning
and return an empty secrets list (graceful degradation).
"""
from unittest.mock import AsyncMock, patch

import pytest

from autored.subagents.credharvester import CredHarvesterOutput, credharvester_subagent
from autored.tools.mimikatz import MimikatzResult


@pytest.mark.asyncio
async def test_credharvester_windows_calls_mimikatz_and_extracts_secrets():
    """Happy path: mimikatz returns two creds (one NTLM, one plaintext).
    Each piece of secret material becomes its own Secret record — NTLM
    hash + plaintext password = 2 secrets per cred block.
    """
    fake_mimikatz = MimikatzResult(
        host_ip="10.10.10.5",
        credentials=[
            {
                "provider": "msv",
                "username": "Administrator",
                "domain": "CORP",
                "ntlm": "aad3b435b51404eeaad3b435b51404ee",
                "sha1": "",
                "sha256": "",
                "password": "",
                "kerberos": "",
            },
            {
                "provider": "tspkg",
                "username": "Administrator",
                "domain": "CORP",
                "ntlm": "",
                "sha1": "",
                "sha256": "",
                "password": "P@ssw0rd123!",
                "kerberos": "",
            },
        ],
    )
    with patch("autored.subagents.credharvester.mimikatz_wrapper") as mock_mim:
        mock_mim.ainvoke = AsyncMock(return_value=fake_mimikatz)
        result = await credharvester_subagent.ainvoke({
            "foothold_id": "fh-001",
            "host_ip": "10.10.10.5",
            "os_type": "windows",
            "engagement_id": "test-eng",
        })
    assert isinstance(result, CredHarvesterOutput)
    assert result.host_ip == "10.10.10.5"
    assert result.mimikatz_result is fake_mimikatz
    # One NTLM hash + one plaintext password → 2 secrets.
    assert len(result.secrets) == 2
    ntlm_secret = next(s for s in result.secrets if s.secret_type == "hash")
    pw_secret = next(s for s in result.secrets if s.secret_type == "password")
    assert ntlm_secret.secret_value == "aad3b435b51404eeaad3b435b51404ee"
    assert pw_secret.secret_value == "P@ssw0rd123!"
    # Each secret's source traces back to mimikatz:<provider>/<username>.
    assert "mimikatz" in ntlm_secret.source
    assert "Administrator" in ntlm_secret.source
    mock_mim.ainvoke.assert_awaited_once()


@pytest.mark.asyncio
async def test_credharvester_linux_defers_secretsdump_to_phase5():
    """Phase 4 contract: on Linux footholds, secretsdump is deferred to
    Phase 5 (no harvested plaintext creds to feed impacket yet). The
    secrets list must be empty and no mimikatz call must be made."""
    with patch("autored.subagents.credharvester.mimikatz_wrapper") as mock_mim, \
         patch("autored.subagents.credharvester.secretsdump") as mock_ss:
        mock_mim.ainvoke = AsyncMock()
        mock_ss.ainvoke = AsyncMock()
        result = await credharvester_subagent.ainvoke({
            "foothold_id": "fh-001",
            "host_ip": "10.10.10.5",
            "os_type": "linux",
            "engagement_id": "test-eng",
        })
    assert isinstance(result, CredHarvesterOutput)
    assert result.secrets == []
    assert result.mimikatz_result is None
    assert result.secretsdump_result is None
    mock_mim.ainvoke.assert_not_awaited()
    mock_ss.ainvoke.assert_not_awaited()


@pytest.mark.asyncio
async def test_credharvester_ad_defers_certipy_to_phase5():
    """Phase 4 contract: on AD footholds, certipy is deferred to Phase 5
    (no harvested domain creds yet). Secrets list empty, no certipy call."""
    with patch("autored.subagents.credharvester.certipy") as mock_cert:
        mock_cert.ainvoke = AsyncMock()
        result = await credharvester_subagent.ainvoke({
            "foothold_id": "fh-001",
            "host_ip": "10.10.10.5",
            "os_type": "ad",
            "engagement_id": "test-eng",
        })
    assert isinstance(result, CredHarvesterOutput)
    assert result.secrets == []
    assert result.certipy_result is None
    mock_cert.ainvoke.assert_not_awaited()


@pytest.mark.asyncio
async def test_credharvester_unknown_os_returns_empty():
    """Unknown os_type → graceful degradation: empty secrets list, no tool calls."""
    with patch("autored.subagents.credharvester.mimikatz_wrapper") as mock_mim:
        mock_mim.ainvoke = AsyncMock()
        result = await credharvester_subagent.ainvoke({
            "foothold_id": "fh-001",
            "host_ip": "10.10.10.5",
            "os_type": "solaris",
            "engagement_id": "test-eng",
        })
    assert isinstance(result, CredHarvesterOutput)
    assert result.secrets == []
    mock_mim.ainvoke.assert_not_awaited()
