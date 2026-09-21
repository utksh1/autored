# tests/unit/tools/test_nmap.py
import pytest
from autored.tools.nmap import _parse_nmap_xml, _build_nmap_cmd, NmapResult


@pytest.fixture
def lame_xml(fixtures_dir):
    return (fixtures_dir / "nmap_lame_quick.xml").read_text()


def test_parse_lame_xml(lame_xml):
    hosts = _parse_nmap_xml(lame_xml)
    assert len(hosts) == 1
    assert hosts[0].ip == "10.10.10.5"
    assert hosts[0].hostname == "lame.htb"
    assert hosts[0].mac == "00:50:56:b9:5c:8c"
    assert len(hosts[0].ports) == 5

    ftp = next(p for p in hosts[0].ports if p.port == 21)
    assert ftp.service == "ftp"
    assert ftp.product == "vsftpd"
    assert ftp.version == "2.3.4"
    assert ftp.state == "open"
    assert ftp.protocol == "tcp"


def test_parse_malformed_xml_raises():
    with pytest.raises(Exception):
        _parse_nmap_xml("<nmaprun><host><address")  # truncated


def test_parse_empty_xml():
    hosts = _parse_nmap_xml('<?xml version="1.0"?><nmaprun></nmaprun>')
    assert hosts == []


def test_build_nmap_cmd_quick():
    cmd = _build_nmap_cmd("10.10.10.5", "quick", None)
    assert cmd[0] == "nmap"
    assert "-oX" in cmd
    assert "-" in cmd  # output to stdout
    assert "--top-ports" in cmd
    assert "100" in cmd
    assert "10.10.10.5" in cmd


def test_build_nmap_cmd_full_with_ports():
    cmd = _build_nmap_cmd("10.10.10.5", "full", "1-1000")
    assert "-p-" in cmd
    assert "-p" in cmd
    assert "1-1000" in cmd


def test_build_nmap_cmd_service():
    cmd = _build_nmap_cmd("10.10.10.5", "service", None)
    assert "-sV" in cmd
    assert "-sC" in cmd


def test_nmap_result_validates_scan_type():
    """Verify Pydantic rejects invalid scan_type values."""
    with pytest.raises(Exception):
        NmapResult(target="10.10.10.5", scan_type="super-scan")  # type: ignore
