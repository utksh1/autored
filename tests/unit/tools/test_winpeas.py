# tests/unit/tools/test_winpeas.py
from autored.tools.winpeas import _parse_winpeas_output, WinpeasResult


def test_parse_winpeas_output(fixtures_dir):
    text = (fixtures_dir / "winpeas_output.txt").read_text()
    result = _parse_winpeas_output(text, "10.10.10.5")
    assert isinstance(result, WinpeasResult)
    # Should find autologon creds
    assert len(result.autologon_credentials) >= 1
    # Should find modifiable services
    assert len(result.modifiable_services) >= 0


def test_parse_winpeas_empty():
    result = _parse_winpeas_output("", "10.10.10.5")
    assert result.autologon_credentials == []
