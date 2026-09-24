"""Tests for the mimikatz tool wrapper (Phase 4, Task 5).

Pattern mirrors the Phase 4 T3 (linpeas / winpeas) wrappers —
``_parse_mimikatz_output`` is exercised directly via a fixture file (so
the regex extraction has a stable, reviewable contract), and the
``mimikatz_wrapper`` ``@tool`` is exercised end-to-end via
``.ainvoke({...})`` with ``_save_raw`` mocked so the test never touches
disk. Per the T5 brief, ``mimikatz_wrapper`` constructs the mimikatz
command string and saves it; real execution is deferred to the Phase 6
FootholdSessionManager (the same Phase 4 stub pattern as linpeas/winpeas).
"""
from __future__ import annotations

import pytest

from autored.config import load_roe
from autored.roe_guard import register_roe
from autored.tools.mimikatz import MimikatzResult, _parse_mimikatz_output, mimikatz_wrapper


def test_parse_mimikatz_output(fixtures_dir):
    """Parser pulls username / NTLM / plaintext-password triples out of the
    msv / tspkg / kerberos blocks of a representative mimikatz stdout fixture."""
    text = (fixtures_dir / "mimikatz_output.txt").read_text()
    result = _parse_mimikatz_output(text, "10.10.10.5")
    assert isinstance(result, MimikatzResult)
    # Should find at least one credential (msv block)
    assert len(result.credentials) >= 1
    # Administrator should appear in at least one block
    assert any(c["username"] == "Administrator" for c in result.credentials)
    # Should find the NTLM hash in the msv block
    assert any(
        "aad3b435b51404eeaad3b435b51404ee" in c.get("ntlm", "")
        for c in result.credentials
    )
    # Should find the plaintext password in the tspkg block
    assert any(
        c.get("password") == "P@ssw0rd123!" for c in result.credentials
    )
    # Should find svc_web / Summer2024! from the kerberos block
    assert any(c["username"] == "svc_web" for c in result.credentials)


def test_parse_mimikatz_empty():
    """Empty stdout must not crash the parser and must yield an empty list."""
    result = _parse_mimikatz_output("", "10.10.10.5")
    assert isinstance(result, MimikatzResult)
    assert result.credentials == []
    assert result.host_ip == "10.10.10.5"


@pytest.mark.asyncio
async def test_mimikatz_wrapper_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, monkeypatch
):
    """Integration test: call the decorated tool end-to-end via .ainvoke().

    Regression catcher for the decorator-stacking bug (Ruling 1 in the SDD
    ledger): ``@tool`` must be applied OUTERMOST and ``@roe_guard`` INNER,
    or the resulting StructuredTool is not callable via ``.ainvoke({...})``.

    Per the T5 brief, ``mimikatz_wrapper`` does NOT actually execute
    subprocess — it constructs the mimikatz command string and persists
    it via ``_save_raw`` so the Phase 6 FootholdSessionManager can replay
    the command against the foothold's shell session. So we mock
    ``_save_raw`` only — no ``run_subprocess`` mock needed for this tool.
    """
    roe = load_roe(sandbox_roe_yaml)
    register_roe("mimikatz-int", roe)

    async def fake_save_raw(*args, **kwargs):
        return "/tmp/fake/mimikatz_cmd.out"

    monkeypatch.setattr("autored.tools.mimikatz._save_raw", fake_save_raw)

    result = await mimikatz_wrapper.ainvoke(
        {
            "foothold_id": "fh-001",
            "host_ip": "10.10.10.5",
            "engagement_id": "mimikatz-int",
        }
    )

    assert isinstance(result, MimikatzResult)
    assert result.host_ip == "10.10.10.5"
    # Phase 4 stub: raw_output_path is set (command was saved) but the
    # credentials list is empty because the tool did not actually execute.
    assert result.raw_output_path == "/tmp/fake/mimikatz_cmd.out"
    assert result.credentials == []
