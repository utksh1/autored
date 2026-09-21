# tests/unit/tools/test_mimikatz.py
from autored.tools.mimikatz import _parse_mimikatz_output, MimikatzResult


def test_parse_mimikatz_output(fixtures_dir):
    text = (fixtures_dir / "mimikatz_output.txt").read_text()
    result = _parse_mimikatz_output(text, "10.10.10.5")
    assert isinstance(result, MimikatzResult)
    assert len(result.credentials) >= 1
    assert any(c["username"] == "Administrator" for c in result.credentials)
    # Should find NTLM hash
    assert any(
        "aad3b435b51404eeaad3b435b51404ee" in c.get("ntlm", "")
        for c in result.credentials
    )
    # Should find plaintext password
    assert any(c.get("password") == "P@ssw0rd123!" for c in result.credentials)


def test_parse_mimikatz_empty():
    result = _parse_mimikatz_output("", "10.10.10.5")
    assert result.credentials == []
