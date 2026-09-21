# tests/unit/tools/test_subfinder.py
import pytest
from autored.tools.subfinder import _parse_subfinder_jsonl, _build_subfinder_cmd, SubdomainList

def test_parse_subfinder_jsonl(fixtures_dir):
    text = (fixtures_dir / "subfinder_lame.json").read_text()
    result = _parse_subfinder_jsonl(text, "lame.htb")
    assert isinstance(result, SubdomainList)
    assert result.domain == "lame.htb"
    assert "www.lame.htb" in result.subdomains
    assert "ftp.lame.htb" in result.subdomains

def test_parse_subfinder_empty():
    result = _parse_subfinder_jsonl("", "example.com")
    assert result.subdomains == []

def test_build_subfinder_cmd():
    cmd = _build_subfinder_cmd("lame.htb")
    assert "subfinder" in cmd[0]
    assert "-d" in cmd
    assert "lame.htb" in cmd
    assert "-json" in cmd
