# tests/unit/tools/test_gobuster_vhost.py
import pytest
from autored.tools.gobuster_vhost import _parse_gobuster_output, _build_gobuster_cmd, VhostList

def test_parse_gobuster_output(fixtures_dir):
    text = (fixtures_dir / "gobuster_vhost_lame.txt").read_text()
    result = _parse_gobuster_output(text, "lame.htb")
    assert isinstance(result, VhostList)
    assert result.domain == "lame.htb"
    assert len(result.vhosts) == 2
    assert result.vhosts[0].hostname == "dev.lame.htb"
    assert result.vhosts[0].status_code == 200

def test_parse_gobuster_empty():
    result = _parse_gobuster_output("", "example.com")
    assert result.vhosts == []

def test_build_gobuster_cmd():
    cmd = _build_gobuster_cmd("http://lame.htb", "/usr/share/wordlists/dirb/common.txt")
    assert "gobuster" in cmd[0]
    assert "vhost" in cmd
    assert "-u" in cmd
    assert "http://lame.htb" in cmd
    assert "-w" in cmd
