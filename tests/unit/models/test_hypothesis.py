import pytest
from autored.models.hypothesis import AttackHypothesis

def test_attack_hypothesis_minimal():
    h = AttackHypothesis(
        rank=1,
        target="10.10.10.56",
        technique="Shellshock (CVE-2014-6271)",
        cve="CVE-2014-6271",
        expected_outcome="RCE as www-data",
        tool="custom",
        confidence=0.85,
        rationale="Apache httpd 2.2.22 with /cgi-bin/ directory",
        prerequisites=["http service accessible", "cgi-bin path discoverable"],
        risks=["may crash apache worker"],
    )
    assert h.rank == 1
    assert h.tool == "custom"
    assert h.tool_module is None
    assert h.command_preview is None
    assert h.confidence == 0.85

def test_attack_hypothesis_with_metasploit():
    h = AttackHypothesis(
        rank=1,
        target="10.10.10.5",
        technique="EternalBlue (MS17-010)",
        cve="CVE-2017-0144",
        expected_outcome="SYSTEM shell",
        tool="metasploit",
        tool_module="exploit/windows/smb/ms17_010_eternalblue",
        confidence=0.9,
        rationale="SMB on port 445 reports Windows XP",
        prerequisites=[],
        risks=["may crash SMB service"],
    )
    assert h.tool == "metasploit"
    assert h.tool_module == "exploit/windows/smb/ms17_010_eternalblue"

def test_attack_hypothesis_rejects_invalid_tool():
    with pytest.raises(Exception):
        AttackHypothesis(
            rank=1, target="x", technique="x", cve=None,
            expected_outcome="x", tool="invalid_tool",
            confidence=0.5, rationale="x", prerequisites=[], risks=[],
        )

def test_attack_hypothesis_rejects_confidence_out_of_range():
    with pytest.raises(Exception):
        AttackHypothesis(
            rank=1, target="x", technique="x", cve=None,
            expected_outcome="x", tool="custom",
            confidence=1.5, rationale="x", prerequisites=[], risks=[],
        )

def test_attack_hypothesis_round_trip_json():
    h = AttackHypothesis(
        rank=2, target="10.10.10.5", technique="t", cve="CVE-2020-1234",
        expected_outcome="eo", tool="sqlmap", confidence=0.7,
        rationale="r", prerequisites=["p1"], risks=["r1"],
        command_preview="sqlmap -u http://target",
    )
    serialized = h.model_dump_json()
    restored = AttackHypothesis.model_validate_json(serialized)
    assert restored == h
