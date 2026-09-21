# tests/unit/tools/test_certipy.py
from autored.tools.certipy import _build_certipy_cmd, CertipyResult


def test_build_certipy_cmd_find():
    cmd = _build_certipy_cmd(
        "find", username="user", password="pass",
        domain="CORP.LOCAL", target="10.10.10.5",
    )
    assert "certipy" in cmd[0]
    assert "find" in cmd
    assert "-u" in cmd
    assert "user@CORP.LOCAL" in cmd
    assert "-p" in cmd
    assert "pass" in cmd


def test_certipy_result_model():
    r = CertipyResult(
        action="find", target="10.10.10.5",
        vulnerable_templates=[], raw_output_path="",
    )
    assert r.action == "find"
