"""Unit tests for the ``_extract_*`` helpers in ``autored.agents.recon``.

These tests directly verify the Phase 1 final-review fixes:

- I1: ``_extract_web_apps`` parses ``host_ip`` and ``port`` from the
  httpx result's ``url`` field instead of emitting orphan
  ``WebApp(host_ip="", port=0)`` records.
- I4: ``_extract_services`` dedupes by ``(host_ip, port, protocol)`` so
  a port reported by both naabu and nmap (or by two sub-agent calls
  against the same host) doesn't produce two ``Service`` rows.

The existing integration tests in ``tests/integration/`` exercise these
helpers end-to-end, but their fixtures use single-source port data and
empty httpx_results, so they don't directly catch the I1/I4 regressions
— these unit tests do.
"""
from __future__ import annotations

from autored.agents.recon import _extract_services, _extract_web_apps
from autored.models import Service, WebApp


# ---------------------------------------------------------------------------
# I1: _extract_web_apps parses host_ip + port from the httpx result URL.
# ---------------------------------------------------------------------------

def test_extract_web_apps_parses_host_ip_and_port_from_url():
    """A well-formed URL with an explicit port populates both fields."""
    results = [{
        "httpx_results": [{
            "url": "http://10.10.10.5:8080/",
            "status_code": 200,
            "title": "Lame",
            "tech_stack": ["Apache"],
            "web_server": "Apache",
        }],
    }]
    apps = _extract_web_apps(results)
    assert len(apps) == 1
    assert apps[0].host_ip == "10.10.10.5"
    assert apps[0].port == 8080
    assert apps[0].status_code == 200
    assert apps[0].title == "Lame"


def test_extract_web_apps_defaults_http_port_to_80():
    """No explicit port + http scheme → 80 (the httpx default for HTTP)."""
    results = [{
        "httpx_results": [{
            "url": "http://10.10.10.5/",
            "status_code": 200,
        }],
    }]
    apps = _extract_web_apps(results)
    assert apps[0].host_ip == "10.10.10.5"
    assert apps[0].port == 80


def test_extract_web_apps_defaults_https_port_to_443():
    """No explicit port + https scheme → 443."""
    results = [{
        "httpx_results": [{
            "url": "https://lame.htb/",
            "status_code": 200,
        }],
    }]
    apps = _extract_web_apps(results)
    assert apps[0].host_ip == "lame.htb"
    assert apps[0].port == 443


def test_extract_web_apps_falls_back_to_orphan_for_malformed_url():
    """Malformed URL preserves the pre-fix orphan behaviour (host_ip="", port=0).

    A bad URL doesn't explode the whole extraction — Phase 2's Vuln Agent
    can skip orphan WebApps by checking for empty ``host_ip``.
    """
    results = [{
        "httpx_results": [{
            "url": "not-a-url",
            "status_code": 200,
        }],
    }]
    apps = _extract_web_apps(results)
    assert len(apps) == 1
    assert apps[0].host_ip == ""
    assert apps[0].port == 0
    assert apps[0].url == "not-a-url"


def test_extract_web_apps_handles_empty_url_gracefully():
    """Empty URL → orphan record, no exception."""
    results = [{
        "httpx_results": [{
            "url": "",
            "status_code": 0,
        }],
    }]
    apps = _extract_web_apps(results)
    assert len(apps) == 1
    assert apps[0].host_ip == ""
    assert apps[0].port == 0


def test_extract_web_apps_emits_no_orphans_for_real_urls():
    """Regression guard for I1: a real httpx result never produces an orphan
    WebApp (one with host_ip="" and port=0) unless the URL itself is
    malformed."""
    results = [{
        "httpx_results": [
            {"url": "http://10.10.10.5/", "status_code": 200},
            {"url": "https://lame.htb:8443/", "status_code": 200},
        ],
    }]
    apps = _extract_web_apps(results)
    assert len(apps) == 2
    for app in apps:
        # Real URLs never produce orphans.
        assert app.host_ip != ""
        assert app.port != 0


# ---------------------------------------------------------------------------
# I4: _extract_services dedupes by (host_ip, port, protocol).
# ---------------------------------------------------------------------------

def _make_deep_scan_result(host_ip: str, ports: list[dict]) -> dict:
    """Build a minimal ``deep_scan`` shape matching NmapResult.model_dump()."""
    return {
        "deep_scan": {
            "target": host_ip,
            "scan_type": "service",
            "hosts": [{
                "ip": host_ip,
                "ports": ports,
            }],
        },
    }


def test_extract_services_dedupes_same_port_reported_by_two_sources():
    """nmap + naabu both reporting port 80/tcp on 10.10.10.5 → 1 Service."""
    port_80 = {"port": 80, "protocol": "tcp", "state": "open", "service": "http"}
    results = [
        _make_deep_scan_result("10.10.10.5", [port_80]),
        _make_deep_scan_result("10.10.10.5", [port_80]),
    ]
    services = _extract_services(results)
    assert len(services) == 1
    assert services[0].host_ip == "10.10.10.5"
    assert services[0].port == 80
    assert services[0].protocol == "tcp"


def test_extract_services_keeps_distinct_ports_on_same_host():
    """Same host, different ports → all kept (no over-deduping)."""
    results = [_make_deep_scan_result("10.10.10.5", [
        {"port": 21, "protocol": "tcp", "state": "open", "service": "ftp"},
        {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
        {"port": 80, "protocol": "tcp", "state": "open", "service": "http"},
    ])]
    services = _extract_services(results)
    assert len(services) == 3
    assert {s.port for s in services} == {21, 22, 80}


def test_extract_services_keeps_same_port_different_protocols():
    """Port 53 on both tcp and udp → 2 Services (key includes protocol)."""
    results = [_make_deep_scan_result("10.10.10.5", [
        {"port": 53, "protocol": "tcp", "state": "open", "service": "domain"},
        {"port": 53, "protocol": "udp", "state": "open", "service": "domain"},
    ])]
    services = _extract_services(results)
    assert len(services) == 2
    assert {s.protocol for s in services} == {"tcp", "udp"}


def test_extract_services_keeps_same_port_different_hosts():
    """Port 80 on two different hosts → 2 Services (key includes host_ip)."""
    results = [
        _make_deep_scan_result("10.10.10.5", [
            {"port": 80, "protocol": "tcp", "state": "open"},
        ]),
        _make_deep_scan_result("10.10.10.6", [
            {"port": 80, "protocol": "tcp", "state": "open"},
        ]),
    ]
    services = _extract_services(results)
    assert len(services) == 2
    assert {s.host_ip for s in services} == {"10.10.10.5", "10.10.10.6"}


def test_extract_services_first_seen_wins():
    """When the same (host, port, protocol) appears twice, the first-seen
    Service (with its product/version info) wins — second is dropped."""
    results = [
        _make_deep_scan_result("10.10.10.5", [
            {"port": 22, "protocol": "tcp", "state": "open",
             "service": "ssh", "product": "OpenSSH", "version": "4.7p1"},
        ]),
        _make_deep_scan_result("10.10.10.5", [
            {"port": 22, "protocol": "tcp", "state": "open",
             "service": "ssh", "product": "DROPBEAR", "version": "0.51"},
        ]),
    ]
    services = _extract_services(results)
    assert len(services) == 1
    # First-seen wins — the OpenSSH result, not the DROPBEAR one.
    assert services[0].product == "OpenSSH"
    assert services[0].version == "4.7p1"


def test_extract_services_ignores_closed_ports():
    """Closed ports are filtered out — only ``state == "open"`` ports produce
    Service rows. (Pre-existing behaviour; this guards against the dedupe
    refactor accidentally including closed ports.)"""
    results = [_make_deep_scan_result("10.10.10.5", [
        {"port": 22, "protocol": "tcp", "state": "open"},
        {"port": 23, "protocol": "tcp", "state": "closed"},
        {"port": 80, "protocol": "tcp", "state": "filtered"},
    ])]
    services = _extract_services(results)
    assert len(services) == 1
    assert services[0].port == 22
