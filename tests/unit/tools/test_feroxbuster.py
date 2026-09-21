# tests/unit/tools/test_feroxbuster.py
import pytest
from autored.tools.feroxbuster import _parse_feroxbuster_jsonl, _build_feroxbuster_cmd, DirResult


def test_parse_feroxbuster_jsonl(fixtures_dir):
    text = (fixtures_dir / "feroxbuster_lame.json").read_text()
    results = _parse_feroxbuster_jsonl(text)
    assert len(results) == 2
    assert results[0].url == "http://10.10.10.5/icons/"
    assert results[0].status_code == 403
    assert results[1].url == "http://10.10.10.5/index.html"
    assert results[1].extension == "html"


def test_parse_feroxbuster_empty():
    assert _parse_feroxbuster_jsonl("") == []


def test_build_feroxbuster_cmd():
    cmd = _build_feroxbuster_cmd("http://10.10.10.5", "/usr/share/wordlists/dirb/common.txt", 3)
    assert "feroxbuster" in cmd[0]
    assert "-u" in cmd
    assert "http://10.10.10.5" in cmd
    assert "-w" in cmd
    assert "/usr/share/wordlists/dirb/common.txt" in cmd
    assert "-d" in cmd
    assert "3" in cmd
    assert "--json" in cmd
