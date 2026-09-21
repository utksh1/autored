# tests/unit/tools/test_bloodhound.py
from autored.tools.bloodhound import _build_bloodhound_cmd, BloodhoundResult


def test_build_bloodhound_cmd():
    cmd = _build_bloodhound_cmd("user", "pass", "CORP.LOCAL", "10.10.10.5")
    assert "bloodhound-python" in cmd[0]
    assert "-u" in cmd
    assert "user" in cmd
    assert "-p" in cmd
    assert "pass" in cmd
    assert "-d" in cmd
    assert "CORP.LOCAL" in cmd
    assert "-c" in cmd
    assert "All" in cmd
    assert "10.10.10.5" in cmd


def test_bloodhound_result_model():
    r = BloodhoundResult(
        domain="CORP.LOCAL", host="10.10.10.5",
        json_output_path="/tmp/bloodhound_data",
        computers=[], users=[], sessions=[],
    )
    assert r.domain == "CORP.LOCAL"
