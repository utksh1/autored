# tests/unit/tools/test_dnsx.py
import pytest
from autored.tools.dnsx import _parse_dnsx_jsonl, _build_dnsx_cmd, DnsResult, DnsRecord

def test_parse_dnsx_jsonl(fixtures_dir):
    text = (fixtures_dir / "dnsx_lame.json").read_text()
    results = _parse_dnsx_jsonl(text)
    assert len(results) == 2
    assert results[0].hostname == "lame.htb"
    assert any(r.record_type == "A" and r.value == "10.10.10.5" for r in results[0].records)
    assert results[1].hostname == "www.lame.htb"
    assert any(r.record_type == "CNAME" for r in results[1].records)

def test_parse_dnsx_empty():
    assert _parse_dnsx_jsonl("") == []

def test_build_dnsx_cmd():
    cmd = _build_dnsx_cmd(["lame.htb", "www.lame.htb"])
    assert "dnsx" in cmd[0]
    assert "-d" in cmd or "-l" in cmd
    assert "-a" in cmd
    "-aaaa" in cmd
    assert "-json" in cmd
