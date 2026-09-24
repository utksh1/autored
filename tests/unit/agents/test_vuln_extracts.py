"""Unit tests for the ``_extract_vulns`` helper in ``autored.agents.vuln``.

These tests directly verify the Phase 2 final-review fix I3:

- The integration test ``test_vuln_node_produces_hypotheses`` exercises
  ``vuln_node`` end-to-end (CVEMatcher + ExploitFinder + Sonnet + critic
  all mocked) and asserts ``"attack_hypotheses" in result`` and
  ``len(result["attack_hypotheses"]) >= 1`` — but it never inspects
  ``result["vulnerabilities"]``. The ``_extract_vulns`` helper that
  converts CVE matches + exploit search results into ``Vulnerability``
  records is therefore untested at the assertion level.

- These unit tests call ``_extract_vulns`` directly with controlled
  ``CveMatch`` / ``ExploitFinderOutput`` fixtures and assert every
  field the helper is supposed to populate (severity mapping, source
  tag, CVE field, title, references).

The direct-import approach is intentional: ``_extract_vulns`` is a
private helper (leading underscore) but it's a pure function with no
side effects, so testing it directly is simpler than mocking the full
``vuln_node`` call chain just to indirect through it. (Same pattern as
``tests/unit/agents/test_recon_extracts.py`` from Phase 1.)
"""
from __future__ import annotations

from autored.agents.vuln import _extract_vulns
from autored.models import Vulnerability
from autored.subagents.cvematcher import CveMatch
from autored.subagents.exploitfinder import ExploitFinderOutput
from autored.tools.nvd import NvdCve
from autored.tools.searchsploit import ExploitEntry


# ---------------------------------------------------------------------------
# I3a: _extract_vulns converts CveMatch → Vulnerability with correct
# severity mapping, source tag, and CVE field.
# ---------------------------------------------------------------------------

def test_extract_vulns_from_cve_matches():
    """CveMatch with NvdCve entries produces Vulnerability rows tagged
    ``source="nvd"`` with the right severity mapping (CRITICAL → critical,
    HIGH → high, etc.) and the right ``cve`` field from ``NvdCve.cve_id``.
    """
    cve_matches = [
        CveMatch(
            service="http",
            host_ip="10.10.10.56",
            port=80,
            product="Apache httpd",
            version="2.2.22",
            cves=[
                NvdCve(
                    cve_id="CVE-2014-6271",
                    description="Shellshock: remote code execution via bash env vars",
                    cvss_score=10.0,
                    severity="CRITICAL",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2014-6271"],
                ),
                NvdCve(
                    cve_id="CVE-2017-5638",
                    description="Another Shellshock-adjacent issue",
                    cvss_score=7.5,
                    severity="HIGH",
                    references=[],
                ),
            ],
        ),
        CveMatch(
            service="ssh",
            host_ip="10.10.10.56",
            port=2222,
            product="OpenSSH",
            version="7.2p2",
            cves=[
                NvdCve(
                    cve_id="CVE-2016-6210",
                    description="User enumeration via timing in OpenSSH",
                    cvss_score=5.3,
                    severity="MEDIUM",
                ),
                NvdCve(
                    cve_id="CVE-2018-15473",
                    description="OpenSSH username enumeration",
                    cvss_score=5.3,
                    severity="MEDIUM",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2018-15473"],
                ),
            ],
        ),
    ]
    vulns = _extract_vulns(cve_matches, [])

    # Four CVEs total → four Vulnerability rows.
    assert len(vulns) == 4
    assert all(isinstance(v, Vulnerability) for v in vulns)

    # Severity mapping: NVD "CRITICAL" → "critical", "HIGH" → "high",
    # "MEDIUM" → "medium".
    by_cve = {v.cve: v for v in vulns}
    assert by_cve["CVE-2014-6271"].severity == "critical"
    assert by_cve["CVE-2017-5638"].severity == "high"
    assert by_cve["CVE-2016-6210"].severity == "medium"
    assert by_cve["CVE-2018-15473"].severity == "medium"

    # All NVD-derived vulns carry source="nvd".
    assert all(v.source == "nvd" for v in vulns)

    # The cve field is copied verbatim from NvdCve.cve_id.
    assert by_cve["CVE-2014-6271"].cve == "CVE-2014-6271"
    assert by_cve["CVE-2018-15473"].cve == "CVE-2018-15473"

    # The host_ip, port, and service are inherited from the parent CveMatch.
    assert by_cve["CVE-2014-6271"].host_ip == "10.10.10.56"
    assert by_cve["CVE-2014-6271"].port == 80
    assert by_cve["CVE-2014-6271"].service == "http"
    assert by_cve["CVE-2018-15473"].port == 2222
    assert by_cve["CVE-2018-15473"].service == "ssh"

    # The cvss_score is copied from NvdCve.cvss_score.
    assert by_cve["CVE-2014-6271"].cvss_score == 10.0
    assert by_cve["CVE-2017-5638"].cvss_score == 7.5

    # References are copied (empty list preserved as empty list).
    assert by_cve["CVE-2014-6271"].references == [
        "https://nvd.nist.gov/vuln/detail/CVE-2014-6271",
    ]
    assert by_cve["CVE-2017-5638"].references == []


def test_extract_vulns_from_cve_matches_lowercases_severity():
    """The severity lookup is case-insensitive — NVD's "High" or "low"
    should also map correctly (defensive against upstream case drift)."""
    cve_matches = [
        CveMatch(
            service="http",
            host_ip="10.10.10.5",
            port=80,
            product="nginx",
            version="1.17.3",
            cves=[
                NvdCve(cve_id="CVE-2021-X", description="d", severity="High"),
                NvdCve(cve_id="CVE-2021-Y", description="d", severity="Low"),
                NvdCve(cve_id="CVE-2021-Z", description="d", severity="Info"),
                NvdCve(cve_id="CVE-2021-W", description="d", severity=None),
            ],
        ),
    ]
    vulns = _extract_vulns(cve_matches, [])
    by_cve = {v.cve: v for v in vulns}
    assert by_cve["CVE-2021-X"].severity == "high"
    assert by_cve["CVE-2021-Y"].severity == "low"
    assert by_cve["CVE-2021-Z"].severity == "info"
    # Unknown / missing severity degrades to "info" (the default).
    assert by_cve["CVE-2021-W"].severity == "info"


# ---------------------------------------------------------------------------
# I3b: _extract_vulns converts ExploitFinderOutput → Vulnerability with
# source="searchsploit", cve=None, and the right title.
# ---------------------------------------------------------------------------

def test_extract_vulns_from_exploit_entries():
    """ExploitFinderOutput with ExploitEntry rows produces Vulnerability
    rows tagged ``source="searchsploit"``, ``cve=None`` (ExploitDB
    entries don't carry CVEs by default), and ``title`` copied from the
    exploit's ``title`` field. ``host_ip`` is left empty because the
    ExploitDB search isn't host-specific — the Exploit Agent will
    re-scope each hit against the live target in Phase 3.
    """
    exploit_outputs = [
        ExploitFinderOutput(
            query="Apache 2.2.22",
            exploits=[
                ExploitEntry(
                    edb_id="34900",
                    title="Apache - Shellshock",
                    author="unknown",
                    date="2014-09-24",
                    type="remote",
                    platform="linux",
                    path="/usr/share/exploitdb/exploits/linux/remote/34900.txt",
                ),
                ExploitEntry(
                    edb_id="34766",
                    title="Apache 2.2.x - mod_status Cross-Site Scripting",
                    type="webapps",
                    platform="php",
                ),
            ],
        ),
        ExploitFinderOutput(
            query="OpenSSH 7.2p2",
            exploits=[
                ExploitEntry(
                    edb_id="45233",
                    title="OpenSSH 7.x - Username Enumeration",
                    type="remote",
                ),
            ],
        ),
    ]
    vulns = _extract_vulns([], exploit_outputs)

    # Three exploit entries → three Vulnerability rows.
    assert len(vulns) == 3
    assert all(isinstance(v, Vulnerability) for v in vulns)

    # All ExploitDB-derived vulns carry source="searchsploit".
    assert all(v.source == "searchsploit" for v in vulns)

    # CVE is None for every ExploitDB hit (no CVE field on ExploitEntry).
    assert all(v.cve is None for v in vulns)

    # host_ip is empty (search wasn't host-specific).
    assert all(v.host_ip == "" for v in vulns)

    # Title is copied from the ExploitEntry.title field.
    titles = {v.title for v in vulns}
    assert "Apache - Shellshock" in titles
    assert "Apache 2.2.x - mod_status Cross-Site Scripting" in titles
    assert "OpenSSH 7.x - Username Enumeration" in titles

    # The reference URL is the ExploitDB permalink derived from edb_id.
    shellshock = next(v for v in vulns if v.title == "Apache - Shellshock")
    assert shellshock.references == [
        "https://www.exploit-db.com/exploits/34900",
    ]


def test_extract_vulns_handles_empty_inputs_gracefully():
    """Empty cve_matches + empty exploit_outputs → empty Vulnerability list
    (no KeyError, no TypeError, no orphan rows)."""
    vulns = _extract_vulns([], [])
    assert vulns == []


def test_extract_vulns_combines_cve_and_exploit_sources():
    """Mixing CveMatch + ExploitFinderOutput yields a single dedup-free list
    that preserves both sources (NVD rows keep their host_ip, ExploitDB
    rows stay host-agnostic)."""
    cve_matches = [
        CveMatch(
            service="http",
            host_ip="10.10.10.5",
            port=80,
            product="nginx",
            version="1.17.3",
            cves=[
                NvdCve(cve_id="CVE-2021-2301", description="d", severity="HIGH"),
            ],
        ),
    ]
    exploit_outputs = [
        ExploitFinderOutput(
            query="nginx 1.17.3",
            exploits=[
                ExploitEntry(edb_id="42", title="nginx exploit", type="remote"),
            ],
        ),
    ]
    vulns = _extract_vulns(cve_matches, exploit_outputs)

    # 1 NVD row + 1 ExploitDB row = 2 total.
    assert len(vulns) == 2
    nvd_rows = [v for v in vulns if v.source == "nvd"]
    edb_rows = [v for v in vulns if v.source == "searchsploit"]
    assert len(nvd_rows) == 1
    assert len(edb_rows) == 1

    # NVD row keeps host scoping; ExploitDB row stays host-agnostic.
    assert nvd_rows[0].host_ip == "10.10.10.5"
    assert edb_rows[0].host_ip == ""
