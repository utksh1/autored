# tests/unit/subagents/test_credharvester.py
import pytest
from unittest.mock import AsyncMock, patch

from autored.models.postex import Secret
from autored.subagents.credharvester import (
    credharvester_subagent,
    CredHarvesterOutput,
)
from autored.tools.mimikatz import MimikatzResult
from autored.tools.secretsdump import SecretsdumpResult
from autored.tools.certipy import CertipyResult


@pytest.mark.asyncio
async def test_credharvester_calls_mimikatz_on_windows():
    """CredHarvester invokes mimikatz_wrapper on Windows footholds and
    converts harvested credentials into Secret records."""
    fake_mimikatz = MimikatzResult(
        host_ip="10.10.10.5",
        credentials=[
            {
                "username": "Administrator",
                "domain": "CORP",
                "ntlm": "31d6cfe0d16ae931b73c59d7e0c089c0",
                "sha1": "",
                "password": "P@ssw0rd123!",
                "provider": "tspkg",
            },
            {
                "username": "svc_sql",
                "domain": "CORP",
                "ntlm": "aad3b435b51404eeaad3b435b51404ee",
                "sha1": "",
                "password": "",
                "provider": "msv",
            },
        ],
    )

    # Mock all three cred-harvest tools — only mimikatz should be invoked
    # for os_type="windows" (the other two would need creds / DC
    # coordinates that the Phase 4 stub doesn't have yet).
    with patch("autored.subagents.credharvester.mimikatz_wrapper") as mock_mimikatz, \
         patch("autored.subagents.credharvester.secretsdump") as mock_secretsdump, \
         patch("autored.subagents.credharvester.certipy") as mock_certipy:
        mock_mimikatz.ainvoke = AsyncMock(return_value=fake_mimikatz)
        mock_secretsdump.ainvoke = AsyncMock(return_value=SecretsdumpResult(host_ip=""))
        mock_certipy.ainvoke = AsyncMock(return_value=CertipyResult(action="", target=""))

        result = await credharvester_subagent.ainvoke({
            "foothold_id": "f1",
            "host_ip": "10.10.10.5",
            "os_type": "windows",
            "engagement_id": "test-eng",
        })

    assert isinstance(result, CredHarvesterOutput)
    assert result.host_ip == "10.10.10.5"
    assert result.mimikatz_result is not None
    assert result.secretsdump_result is None
    assert result.certipy_result is None

    # The Administrator's plaintext + the svc_sql NTLM hash must both
    # surface as Secret records.
    assert len(result.secrets) >= 2
    assert any(
        s.secret_type == "password" and s.secret_value == "P@ssw0rd123!"
        for s in result.secrets
    )
    assert any(
        s.secret_type == "hash" and "aad3b435" in s.secret_value
        for s in result.secrets
    )
    # All secrets carry the source host IP for traceability.
    assert all(isinstance(s, Secret) for s in result.secrets)
    assert all(s.host_ip == "10.10.10.5" for s in result.secrets)

    # mimikatz was the only one invoked; secretsdump/certipy were not.
    mock_mimikatz.ainvoke.assert_awaited_once()
    mock_secretsdump.ainvoke.assert_not_awaited()
    mock_certipy.ainvoke.assert_not_awaited()
