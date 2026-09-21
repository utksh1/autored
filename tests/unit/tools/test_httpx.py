# tests/unit/tools/test_httpx.py
import pytest
from autored.tools.httpx_tool import _parse_httpx_json, _build_httpx_cmd, HttpxResult


def test_parse_httpx_json(fixtures_dir):
    text = (fixtures_dir / "httpx_lame.json").read_text()
    results = _parse_httpx_json(text)
    assert len(results) == 1
    r = results[0]
    assert r.url == "http://10.10.10.5"
    assert r.status_code == 301
    assert "Apache" in r.tech_stack
    assert r.web_server == "Apache/2.2.8 (Ubuntu) DAV/2"
    assert r.redirects is True
    assert r.final_url == "https://10.10.10.5/"


def test_parse_httpx_empty():
    assert _parse_httpx_json("") == []


def test_build_httpx_cmd():
    cmd = _build_httpx_cmd(["10.10.10.5"], [80, 443])
    assert "httpx" in cmd[0]
    assert "-u" in cmd or "-l" in cmd  # accepts single or list
    assert "-tech-detect" in cmd
    assert "-status-code" in cmd
    assert "-json" in cmd
