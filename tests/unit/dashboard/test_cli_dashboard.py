"""CLI --dashboard flag wiring tests."""
import asyncio

import pytest
import typer
from typer.testing import CliRunner

from autored.cli import app

runner = CliRunner()


def test_tui_and_dashboard_rejected() -> None:
    result = runner.invoke(
        app,
        ["run", "--target", "10.0.0.1", "--roe", "roe-sandbox.yaml",
         "--tui", "--dashboard"],
    )
    assert result.exit_code != 0
    assert "not both" in result.output.lower() or "--tui" in result.output


def test_run_accepts_dashboard_options(monkeypatch) -> None:
    """--dashboard-port parses and the guard passes; abort deterministically
    right after option parsing by short-circuiting load_roe."""
    def _abort(*args, **kwargs):
        raise typer.Exit(code=3)  # sentinel: we got past parsing + guard

    monkeypatch.setattr("autored.config.load_roe", _abort)
    result = runner.invoke(
        app,
        ["run", "--target", "10.0.0.1", "--roe", "roe-sandbox.yaml",
         "--dashboard-port", "9999"],
    )
    assert result.exit_code == 3  # 2 = unknown option, 1 = guard fired


@pytest.mark.asyncio
async def test_supervised_server_survives_crash():
    """A raising dashboard server must not propagate into the run."""
    from autored.dashboard.server import run_dashboard_supervised

    async def exploding():
        raise RuntimeError("uvicorn exploded")

    task = asyncio.create_task(exploding())
    await run_dashboard_supervised(task)  # must not raise
    assert task.done()


@pytest.mark.asyncio
async def test_supervised_server_clean_shutdown():
    from autored.dashboard.server import run_dashboard_supervised

    started = asyncio.Event()

    async def quick_server():
        started.set()
        await asyncio.sleep(10)

    task = asyncio.create_task(quick_server())
    await asyncio.wait_for(started.wait(), timeout=1.0)
    await run_dashboard_supervised(task, shutdown=True)
    assert task.cancelled() or task.done()
