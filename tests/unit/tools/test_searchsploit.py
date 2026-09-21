import pytest
from autored.tools.searchsploit import _parse_searchsploit_json, _build_searchsploit_cmd, SearchsploitResult

def test_parse_searchsploit_json(fixtures_dir):
    import json
    text = (fixtures_dir / "searchsploit_nginx.json").read_text()
    data = json.loads(text)
    result = _parse_searchsploit_json(data, "nginx")
    assert isinstance(result, SearchsploitResult)
    assert result.query == "nginx"
    assert len(result.exploits) == 2
    assert result.exploits[0].edb_id == "41081"
    assert "Nginx" in result.exploits[0].title

def test_parse_searchsploit_empty():
    result = _parse_searchsploit_json({"RESULTS_SEARCH": []}, "test")
    assert result.exploits == []

def test_build_searchsploit_cmd():
    cmd = _build_searchsploit_cmd("nginx 1.17.3")
    assert "searchsploit" in cmd[0]
    assert "--json" in cmd
    assert "nginx 1.17.3" in cmd
