# tests/unit/tools/test_naabu.py
import pytest
from autored.tools.naabu import _parse_naabu_jsonl, _build_naabu_cmd, PortList


def test_parse_naabu_jsonl(fixtures_dir):
    text = (fixtures_dir / "naabu_lame.jsonl").read_text()
    ports = _parse_naabu_jsonl(text)
    assert len(ports) == 5
    assert ports[0].port == 21
    assert ports[0].protocol == "tcp"
    assert ports[0].host == "10.10.10.5"


def test_parse_naabu_empty():
    ports = _parse_naabu_jsonl("")
    assert ports == []


def test_build_naabu_cmd():
    cmd = _build_naabu_cmd("10.10.10.5", "top-1000")
    assert cmd[0] == "naabu"
    assert "-host" in cmd
    assert "10.10.10.5" in cmd
    assert "-port" in cmd
    assert "top-1000" in cmd
    assert "-json" in cmd
