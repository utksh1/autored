"""Tests for the nuclei tool wrapper (Phase 1, Task 10)."""
import pytest

from autored.config import load_roe
from autored.roe_guard import register_roe
from autored.subprocess_runner import SubprocessResult
from autored.tools.nuclei import (
    NucleiOutput,
    NucleiResult,
    _build_nuclei_cmd,
    _parse_nuclei_jsonl,
    nuclei_scan,
)


def test_parse_nuclei_jsonl(fixtures_dir):
    text = (fixtures_dir / "nuclei_lame.jsonl").read_text()
    results = _parse_nuclei_jsonl(text)
    assert len(results) == 2
    assert results[0].template_id == "CVE-2011-2523"
    assert results[0].severity == "high"
    assert results[0].cve is None or "CVE" in results[0].template_id  # template-id may contain CVE
    assert results[1].severity == "critical"


def test_parse_nuclei_empty():
    assert _parse_nuclei_jsonl("") == []


def test_build_nuclei_cmd():
    cmd = _build_nuclei_cmd("10.10.10.5", ["cves/", "vulnerabilities/"])
    assert "nuclei" in cmd[0]
    assert "-u" in cmd
    assert "10.10.10.5" in cmd
    assert "-jsonl" in cmd
    assert any("cves/" in c for c in cmd)


@pytest.mark.asyncio
async def test_nuclei_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, fixtures_dir, monkeypatch
):
    """Integration test: call the decorated tool end-to-end via .ainvoke().

    Regression catcher for the decorator-stacking bug (C1+C2 from Batch A
    review): the brief's spec'd ``@roe_guard`` over ``@tool`` order produced
    a StructuredTool that was not callable via ``.ainvoke({...})``
    (``TypeError: 'StructuredTool' object is not callable``). With the
    swapped order (``@tool`` outermost, ``@roe_guard`` inner), the
    StructuredTool's underlying coroutine is a regular async def, and
    ``.ainvoke({...})`` dispatches correctly through the RoE wrapper.

    Note: ``_save_raw`` is imported into ``nuclei``'s namespace via
    ``from autored.tools.nmap import _save_raw``, so the patch target must
    be ``autored.tools.nuclei._save_raw`` to intercept the call from
    inside ``nuclei_scan``.
    """
    # 1. Register a RoE for the test engagement.
    roe = load_roe(sandbox_roe_yaml)
    register_roe("nuclei-int", roe)

    # 2. Mock run_subprocess to return the fixture JSONL as stdout.
    nuclei_jsonl = (fixtures_dir / "nuclei_lame.jsonl").read_text()

    async def fake_run_subprocess(cmd, timeout=900):
        return SubprocessResult(
            stdout=nuclei_jsonl,
            stderr="",
            returncode=0,
            duration_sec=0.4,
            command=" ".join(cmd),
        )

    monkeypatch.setattr("autored.tools.nuclei.run_subprocess", fake_run_subprocess)

    # 3. Mock _save_raw to a no-op so the test doesn't touch disk.
    async def fake_save_raw(*args, **kwargs):
        return ""

    monkeypatch.setattr("autored.tools.nuclei._save_raw", fake_save_raw)

    # 4. Call the tool via .ainvoke({...}).
    result = await nuclei_scan.ainvoke(
        {
            "target": "10.10.10.5",
            "templates": ["cves/", "vulnerabilities/"],
            "engagement_id": "nuclei-int",
        }
    )

    # 5. Assert the returned object is the right Pydantic model with the
    #    expected fields populated.
    assert isinstance(result, NucleiOutput)
    assert result.target == "10.10.10.5"
    assert len(result.results) == 2
    assert isinstance(result.results[0], NucleiResult)
    assert result.results[0].template_id == "CVE-2011-2523"
    assert result.results[0].severity == "high"
    assert result.results[1].severity == "critical"
