# tests/unit/tools/test_secretsdump.py
from autored.tools.secretsdump import _parse_secretsdump_output, SecretsdumpResult


def test_parse_secretsdump_output(fixtures_dir):
    text = (fixtures_dir / "secretsdump_output.txt").read_text()
    result = _parse_secretsdump_output(text, "10.10.10.5")
    assert isinstance(result, SecretsdumpResult)
    assert len(result.hashes) >= 2  # Administrator + Guest
    assert any(h["username"] == "Administrator" for h in result.hashes)
    assert any(
        "31d6cfe0d16ae931b73c59d7e0c089c0" in h["nthash"] for h in result.hashes
    )


def test_parse_secretsdump_empty():
    result = _parse_secretsdump_output("", "10.10.10.5")
    assert result.hashes == []
