"""CLI --dashboard flag wiring tests."""
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


def test_run_accepts_dashboard_options() -> None:
    # Option parsing only: an unknown --dashboard flag would exit 2 before
    # any RoE loading. roe-sandbox.yaml exists at repo root (used by README).
    result = runner.invoke(
        app,
        ["run", "--target", "10.0.0.1", "--roe", "roe-sandbox.yaml",
         "--no-dashboard"],
    )
    assert result.exit_code != 2  # 2 = usage error; anything else means flag parsed
