"""Tests for the searchsploit tool wrapper (Phase 2, Task 5).

Mirrors the Phase 1 tool-wrapper pattern (nmap/nuclei/httpx): the brief
spec'd ``@roe_guard`` over ``@tool`` decorator order, but Ruling 1 in the
Phase 1 SDD ledger established that ``@tool`` must be OUTERMOST and
``@roe_guard`` INNER (otherwise the resulting ``StructuredTool`` is not
callable via ``.ainvoke({...})``). The integration test below exercises
the swapped order.
"""

import json

import pytest

from autored.config import load_roe
from autored.roe_guard import register_roe
from autored.subprocess_runner import SubprocessResult
from autored.tools.searchsploit import (
    ExploitEntry,
    SearchsploitResult,
    _build_searchsploit_cmd,
    _parse_searchsploit_json,
    searchsploit_query,
)


def test_parse_searchsploit_json(fixtures_dir):
    text = (fixtures_dir / "searchsploit_nginx.json").read_text()
    data = json.loads(text)
    result = _parse_searchsploit_json(data, "nginx")
    assert isinstance(result, SearchsploitResult)
    assert result.query == "nginx"
    assert len(result.exploits) == 2
    assert result.exploits[0].edb_id == "41081"
    assert "Nginx" in result.exploits[0].title


def test_parse_searchsploit_empty():
    result = _parse_searchsploit_json({"RESULTS_SEARCH": []}, "test")
    assert result.exploits == []


def test_build_searchsploit_cmd():
    cmd = _build_searchsploit_cmd("nginx 1.17.3")
    assert "searchsploit" in cmd[0]
    assert "--json" in cmd
    assert "nginx 1.17.3" in cmd


@pytest.mark.asyncio
async def test_searchsploit_query_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, fixtures_dir, monkeypatch
):
    """Integration test: call the decorated tool end-to-end via .ainvoke().

    Regression catcher for the decorator-stacking bug (Ruling 1 in the
    Phase 1 SDD ledger): ``@tool`` must be applied OUTERMOST and
    ``@roe_guard`` INNER. The brief spec'd the opposite order (``@roe_guard``
    over ``@tool``), which produces a StructuredTool that is not callable
    via ``.ainvoke({...})`` (``TypeError: 'StructuredTool' object is not
    callable``). With the swapped order, the StructuredTool's underlying
    coroutine is a regular async def, and ``.ainvoke({...})`` dispatches
    correctly through the RoE wrapper.

    Note: ``_save_raw`` is imported into ``searchsploit``'s namespace via
    ``from autored.tools.nmap import _save_raw``, so the patch target must
    be ``autored.tools.searchsploit._save_raw`` (not
    ``autored.tools.nmap._save_raw``) to intercept the call from inside
    ``searchsploit_query``.
    """
    # 1. Register a RoE for the test engagement.
    roe = load_roe(sandbox_roe_yaml)
    register_roe("searchsploit-int", roe)

    # 2. Mock run_subprocess to return the fixture JSON as stdout.
    searchsploit_json = (fixtures_dir / "searchsploit_nginx.json").read_text()

    async def fake_run_subprocess(cmd, timeout=60):
        return SubprocessResult(
            stdout=searchsploit_json,
            stderr="",
            returncode=0,
            duration_sec=0.3,
            command=" ".join(cmd),
        )

    monkeypatch.setattr("autored.tools.searchsploit.run_subprocess", fake_run_subprocess)

    # 3. Mock _save_raw to a no-op so the test doesn't touch disk.
    async def fake_save_raw(*args, **kwargs):
        return ""

    monkeypatch.setattr("autored.tools.searchsploit._save_raw", fake_save_raw)

    # 4. Call the tool via .ainvoke({...}).
    result = await searchsploit_query.ainvoke(
        {
            "query": "nginx 1.17.3",
            "engagement_id": "searchsploit-int",
        }
    )

    # 5. Assert the returned object is the right Pydantic model with the
    #    expected fields populated.
    assert isinstance(result, SearchsploitResult)
    assert result.query == "nginx 1.17.3"
    assert len(result.exploits) == 2
    e0 = result.exploits[0]
    assert isinstance(e0, ExploitEntry)
    assert e0.edb_id == "41081"
    assert "Nginx" in e0.title
    assert e0.author == "metacom"
    assert e0.date == "2016-12-29"
    assert e0.type == "dos"
    assert e0.platform == "linux"
    assert e0.path == "/usr/share/exploitdb/exploits/linux/dos/41081.py"
    e1 = result.exploits[1]
    assert e1.edb_id == "40898"
    assert e1.path == "/usr/share/exploitdb/exploits/linux/dos/40898.c"
    assert result.command  # non-empty after monkeypatched subprocess
    assert result.duration_sec == 0.3


@pytest.mark.asyncio
async def test_searchsploit_query_handles_malformed_stdout(sandbox_roe_yaml, monkeypatch):
    """Review Focus: searchsploit emits non-JSON stdout (e.g. an error banner).

    The wrapper's ``try/except json.JSONDecodeError`` block returns an empty
    ``SearchsploitResult`` (just ``query=`` set) rather than crashing the
    agent. Raw artefacts are still saved before the parse attempt.
    """
    roe = load_roe(sandbox_roe_yaml)
    register_roe("searchsploit-bad", roe)

    async def fake_run_subprocess(cmd, timeout=60):
        return SubprocessResult(
            stdout="[-] searchsploit: database not found, run searchsploit --update\n",
            stderr="",
            returncode=1,
            duration_sec=0.1,
            command=" ".join(cmd),
        )

    monkeypatch.setattr("autored.tools.searchsploit.run_subprocess", fake_run_subprocess)

    async def fake_save_raw(*args, **kwargs):
        return ""

    monkeypatch.setattr("autored.tools.searchsploit._save_raw", fake_save_raw)

    result = await searchsploit_query.ainvoke(
        {
            "query": "nginx 1.17.3",
            "engagement_id": "searchsploit-bad",
        }
    )

    assert isinstance(result, SearchsploitResult)
    assert result.query == "nginx 1.17.3"
    assert result.exploits == []
