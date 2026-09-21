# tests/unit/tools/test_nuclei.py
import pytest
from autored.tools.nuclei import _parse_nuclei_jsonl, _build_nuclei_cmd, NucleiResult


def test_parse_nuclei_jsonl(fixtures_dir):
    text = (fixtures_dir / "nuclei_lame.jsonl").read_text()
    results = _parse_nuclei_jsonl(text)
    assert len(results) == 2
    assert results[0].template_id == "CVE-2011-2523"
    assert results[0].severity == "high"
    assert results[0].cve is None or "CVE" in results[0].template_id  # template-id may contain CVE
    assert results[1].severity == "critical"


def test_parse_nuclei_empty():
    assert _parse_nuclei_jsonl("") == []


def test_build_nuclei_cmd():
    cmd = _build_nuclei_cmd("10.10.10.5", ["cves/", "vulnerabilities/"])
    assert "nuclei" in cmd[0]
    assert "-u" in cmd
    assert "10.10.10.5" in cmd
    assert "-jsonl" in cmd
    assert any("cves/" in c for c in cmd)
