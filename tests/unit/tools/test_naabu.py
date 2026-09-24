"""Tests for the naabu tool wrapper (Phase 1, Task 8)."""
import pytest

from autored.config import load_roe
from autored.roe_guard import register_roe
from autored.subprocess_runner import SubprocessResult
from autored.tools.naabu import (
    PortList,
    _build_naabu_cmd,
    _parse_naabu_jsonl,
    naabu_scan,
)


def test_parse_naabu_jsonl(fixtures_dir):
    text = (fixtures_dir / "naabu_lame.jsonl").read_text()
    ports = _parse_naabu_jsonl(text)
    assert len(ports) == 5
    assert ports[0].port == 21
    assert ports[0].protocol == "tcp"
    assert ports[0].host == "10.10.10.5"


def test_parse_naabu_empty():
    ports = _parse_naabu_jsonl("")
    assert ports == []


def test_build_naabu_cmd():
    cmd = _build_naabu_cmd("10.10.10.5", "top-1000")
    assert cmd[0] == "naabu"
    assert "-host" in cmd
    assert "10.10.10.5" in cmd
    assert "-port" in cmd
    assert "top-1000" in cmd
    assert "-json" in cmd


def test_portlist_model_holds_target_and_command():
    """PortList carries the target + raw artefact path back to the agent."""
    pl = PortList(target="10.10.10.5", raw_output_path="x", command="naabu ...")
    assert pl.target == "10.10.10.5"
    assert pl.ports == []
    assert pl.duration_sec == 0.0


@pytest.mark.asyncio
async def test_naabu_ainvoke_works_with_roe_guard(
    sandbox_roe_yaml, fixtures_dir, monkeypatch
):
    """Integration test: call the decorated tool end-to-end via .ainvoke().

    Regression catcher for the decorator-stacking bug (C1+C2): the old
    ``@roe_guard`` over ``@tool`` order produced a StructuredTool that was
    not callable via ``.ainvoke({...})``. With the swapped order
    (``@tool`` outermost, ``@roe_guard`` inner), the StructuredTool's
    underlying coroutine is a regular async def, and ``.ainvoke({...})``
    dispatches correctly through the RoE wrapper.

    Note: ``_save_raw`` is imported into ``naabu``'s namespace via
    ``from autored.tools.nmap import _save_raw``, so the patch target must
    be ``autored.tools.naabu._save_raw`` (not ``autored.tools.nmap._save_raw``)
    to intercept the call from inside ``naabu_scan``.
    """
    # 1. Register a RoE for the test engagement.
    roe = load_roe(sandbox_roe_yaml)
    register_roe("naabu-int", roe)

    # 2. Mock run_subprocess to return the fixture JSONL as stdout.
    naabu_jsonl = (fixtures_dir / "naabu_lame.jsonl").read_text()

    async def fake_run_subprocess(cmd, timeout=300):
        return SubprocessResult(
            stdout=naabu_jsonl,
            stderr="",
            returncode=0,
            duration_sec=0.3,
            command=" ".join(cmd),
        )

    monkeypatch.setattr("autored.tools.naabu.run_subprocess", fake_run_subprocess)

    # 3. Mock _save_raw to a no-op so the test doesn't touch disk. The patch
    #    target is naabu's namespace because ``from x import y`` copies the
    #    reference at import time — patching the source module's attribute
    #    wouldn't affect the local binding.
    async def fake_save_raw(*args, **kwargs):
        return ""

    monkeypatch.setattr("autored.tools.naabu._save_raw", fake_save_raw)

    # 4. Call the tool via .ainvoke({...}).
    result = await naabu_scan.ainvoke(
        {
            "target": "10.10.10.5",
            "ports": "top-1000",
            "engagement_id": "naabu-int",
        }
    )

    # 5. Assert the returned object is the right Pydantic model with the
    #    expected fields populated.
    assert isinstance(result, PortList)
    assert result.target == "10.10.10.5"
    assert len(result.ports) == 5
    assert result.ports[0].port == 21
    assert result.ports[0].protocol == "tcp"
    assert result.ports[0].host == "10.10.10.5"
