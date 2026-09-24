"""Tests for the nmap tool wrapper (Phase 1, Task 7)."""
import pytest

from autored.config import load_roe
from autored.roe_guard import register_roe
from autored.subprocess_runner import SubprocessResult
from autored.tools.nmap import (
    NmapResult,
    _build_nmap_cmd,
    _parse_nmap_xml,
    nmap_scan,
)


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
    """Verify Pydantic rejects invalid scan_type values.

    Review focus: hallucinated flag rejection. ``scan_type`` is constrained
    to the canonical 5-mode Literal on both the function signature and the
    result model, so an agent cannot smuggle an arbitrary scan_type through
    the result model.
    """
    with pytest.raises(Exception):
        NmapResult(target="10.10.10.5", scan_type="super-scan")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_nmap_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, fixtures_dir, monkeypatch
):
    """Integration test: call the decorated tool end-to-end via .ainvoke().

    Regression catcher for the decorator-stacking bug (C1+C2): the old
    ``@roe_guard`` over ``@tool`` order produced a StructuredTool that was
    not callable via ``.ainvoke({...})`` (``TypeError: 'StructuredTool'
    object is not callable``). The unit tests above only exercised the
    parser directly, so the bug went undetected.

    With the swapped order (``@tool`` outermost, ``@roe_guard`` inner),
    the StructuredTool's underlying coroutine is a regular async def, and
    ``.ainvoke({...})`` dispatches correctly through the RoE wrapper.
    """
    # 1. Register a RoE for the test engagement (loaded from the sandbox YAML).
    roe = load_roe(sandbox_roe_yaml)
    register_roe("nmap-int", roe)

    # 2. Mock run_subprocess to return the fixture XML as stdout.
    nmap_xml = (fixtures_dir / "nmap_lame_quick.xml").read_text()

    async def fake_run_subprocess(cmd, timeout=600):
        return SubprocessResult(
            stdout=nmap_xml,
            stderr="",
            returncode=0,
            duration_sec=0.5,
            command=" ".join(cmd),
        )

    monkeypatch.setattr("autored.tools.nmap.run_subprocess", fake_run_subprocess)

    # 3. Mock _save_raw to a no-op so the test doesn't touch disk.
    async def fake_save_raw(*args, **kwargs):
        return ""

    monkeypatch.setattr("autored.tools.nmap._save_raw", fake_save_raw)

    # 4. Call the tool via .ainvoke({...}) — the only correct way to call a
    #    StructuredTool. Calling nmap_scan(target=...) directly would raise
    #    TypeError because StructuredTool is not callable.
    result = await nmap_scan.ainvoke(
        {
            "target": "10.10.10.5",
            "scan_type": "quick",
            "engagement_id": "nmap-int",
        }
    )

    # 5. Assert the returned object is the right Pydantic model with the
    #    expected fields populated.
    assert isinstance(result, NmapResult)
    assert result.target == "10.10.10.5"
    assert result.scan_type == "quick"
    assert len(result.hosts) >= 1
    assert result.hosts[0].ip == "10.10.10.5"
    assert result.hosts[0].hostname == "lame.htb"
    assert len(result.hosts[0].ports) == 5
