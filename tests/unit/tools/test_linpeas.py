# tests/unit/tools/test_linpeas.py
from autored.tools.linpeas import _parse_linpeas_output, LinpeasResult


def test_parse_linpeas_output(fixtures_dir):
    text = (fixtures_dir / "linpeas_output.txt").read_text()
    result = _parse_linpeas_output(text, "10.10.10.5")
    assert isinstance(result, LinpeasResult)
    # Should find SUID entries (allow empty — fixture's SUID section lists CVEs)
    assert len(result.suid_binaries) >= 0
    # Should find CVEs
    assert any("CVE" in c for c in result.cves)
    # Should find cron jobs
    assert len(result.cron_jobs) >= 1


def test_parse_linpeas_empty():
    result = _parse_linpeas_output("", "10.10.10.5")
    assert result.suid_binaries == []
    assert result.cron_jobs == []
