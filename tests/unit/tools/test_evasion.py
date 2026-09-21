# tests/unit/tools/test_evasion.py
from autored.tools.evasion import _build_amsi_bypass, _build_log_clear, EvasionResult


def test_build_amsi_bypass():
    cmd = _build_amsi_bypass()
    assert len(cmd) > 0
    # Should be a PowerShell command that patches amsi.dll
    cmd_str = " ".join(cmd)
    assert "amsi" in cmd_str.lower() or "reflection" in cmd_str.lower()


def test_build_log_clear():
    cmd = _build_log_clear("all")  # all = Security, System, Application
    cmd_str = " ".join(cmd)
    assert "wevtutil" in cmd_str or "Clear-EventLog" in cmd_str


def test_evasion_result_model():
    r = EvasionResult(technique="amsi_bypass", host_ip="10.10.10.5",
                      success=True, command="...")
    assert r.technique == "amsi_bypass"
