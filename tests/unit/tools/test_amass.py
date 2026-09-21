# tests/unit/tools/test_amass.py
import pytest
from autored.tools.amass import _parse_amass_jsonl, _build_amass_cmd
from autored.tools.subfinder import SubdomainList

def test_parse_amass_jsonl(fixtures_dir):
    text = (fixtures_dir / "amass_lame.json").read_text()
    result = _parse_amass_jsonl(text, "lame.htb")
    assert isinstance(result, SubdomainList)
    assert result.domain == "lame.htb"
    assert "lame.htb" in result.subdomains
    assert "mail.lame.htb" in result.subdomains

def test_parse_amass_empty():
    result = _parse_amass_jsonl("", "example.com")
    assert result.subdomains == []

def test_build_amass_cmd():
    cmd = _build_amass_cmd("lame.htb")
    assert "amass" in cmd[0]
    assert "enum" in cmd
    assert "-passive" in cmd
    assert "-d" in cmd
    assert "lame.htb" in cmd
