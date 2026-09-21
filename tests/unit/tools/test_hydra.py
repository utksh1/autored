# tests/unit/tools/test_hydra.py
import pytest
from autored.tools.hydra import _build_hydra_cmd, _parse_hydra_output, BruteResult

def test_build_hydra_cmd():
    cmd = _build_hydra_cmd("10.10.10.5", "ssh", "/tmp/users.txt", "/tmp/pass.txt")
    assert "hydra" in cmd[0]
    assert "-L" in cmd
    assert "/tmp/users.txt" in cmd
    assert "-P" in cmd
    assert "/tmp/pass.txt" in cmd
    assert "ssh://10.10.10.5" in cmd

def test_parse_hydra_output_found(fixtures_dir):
    text = (fixtures_dir / "hydra_output.txt").read_text()
    result = _parse_hydra_output(text, "10.10.10.5", "ssh")
    assert result.success is True
    assert len(result.credentials) == 2
    assert result.credentials[0].username == "root"
    assert result.credentials[0].password == "toor"

def test_parse_hydra_output_not_found():
    text = "0 of 1 target successfully completed, 0 valid passwords found"
    result = _parse_hydra_output(text, "10.10.10.5", "ssh")
    assert result.success is False
    assert result.credentials == []
