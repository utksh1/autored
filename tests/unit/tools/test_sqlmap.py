# tests/unit/tools/test_sqlmap.py
import pytest
from autored.tools.sqlmap import _build_sqlmap_cmd, _parse_sqlmap_output, SqlmapResult

def test_build_sqlmap_cmd_basic():
    cmd = _build_sqlmap_cmd("http://10.10.10.5/page?id=1", None, None)
    assert "sqlmap" in cmd[0]
    assert "-u" in cmd
    assert "http://10.10.10.5/page?id=1" in cmd
    assert "--batch" in cmd

def test_build_sqlmap_cmd_with_options():
    cmd = _build_sqlmap_cmd("http://target", ["--forms", "--level=3"], "/tmp/output")
    assert "--forms" in cmd
    assert "--level=3" in cmd
    assert "--output-dir" in cmd
    assert "/tmp/output" in cmd

def test_parse_sqlmap_output_vulnerable(fixtures_dir):
    text = (fixtures_dir / "sqlmap_output.txt").read_text()
    result = _parse_sqlmap_output(text, "http://target")
    assert result.vulnerable is True
    assert len(result.injection_points) >= 1
    assert "boolean-based blind" in result.injection_points[0].type
    assert result.dbms == "MySQL >= 5.0"

def test_parse_sqlmap_output_not_vulnerable():
    text = "all tested parameters do not appear to be injectable"
    result = _parse_sqlmap_output(text, "http://target")
    assert result.vulnerable is False
    assert result.injection_points == []
