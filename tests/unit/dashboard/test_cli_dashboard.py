"""CLI --dashboard flag wiring tests."""
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
