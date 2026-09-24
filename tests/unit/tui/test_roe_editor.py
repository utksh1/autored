"""RoEEditorScreen + roe-wizard CLI tests (Phase 6 Task 17, spec §17.5/§8.3)."""
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner
from textual.widgets import TextArea

from autored.cli import app
from autored.tui.app import AutoRedApp
from autored.tui.screens.roe_editor import RoEEditorScreen

runner = CliRunner()

VALID_ROE_YAML = """\
engagement_name: "Editor Test"
operator: operator
operator_signature: signed
allowed_ips: ["10.0.0.5"]
allowed_techniques: ["*"]
persistence_allowed: false
evasion_allowed: false
exfiltration_allowed: false
data_destruction_allowed: false
kernel_exploits_allowed: false
hitl_mode: auto_approve
"""


async def test_roe_editor_loads_and_validates(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    roe_path = tmp_path / "roe-test.yaml"
    roe_path.write_text(VALID_ROE_YAML)

    screen = RoEEditorScreen(str(roe_path))
    app = AutoRedApp()
    async with app.run_test() as pilot:
        app.push_screen(screen)
        await pilot.pause()
        text_area = screen.query_one(TextArea)
        assert "Editor Test" in text_area.text
        # Valid YAML loaded → no errors in the status line
        assert screen.validation_errors == []


async def test_roe_editor_flags_invalid_yaml(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    roe_path = tmp_path / "roe-bad.yaml"
    roe_path.write_text("not: [valid: yaml")

    screen = RoEEditorScreen(str(roe_path))
    app = AutoRedApp()
    async with app.run_test() as pilot:
        app.push_screen(screen)
        await pilot.pause()
        assert screen.validation_errors  # errors surfaced, not crashed


async def test_roe_editor_save_writes_valid_yaml(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    roe_path = tmp_path / "roe-save.yaml"
    roe_path.write_text(VALID_ROE_YAML)

    screen = RoEEditorScreen(str(roe_path))
    app = AutoRedApp()
    async with app.run_test() as pilot:
        app.push_screen(screen)
        await pilot.pause()
        text_area = screen.query_one(TextArea)
        text_area.text = VALID_ROE_YAML.replace("Editor Test", "Renamed Engagement")
        await pilot.pause()
        screen.action_save()
        await pilot.pause()

    saved = roe_path.read_text()
    assert "Renamed Engagement" in saved


async def test_roe_editor_refuses_to_save_invalid(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    roe_path = tmp_path / "roe-nosave.yaml"
    original = VALID_ROE_YAML
    roe_path.write_text(original)

    screen = RoEEditorScreen(str(roe_path))
    app = AutoRedApp()
    async with app.run_test() as pilot:
        app.push_screen(screen)
        await pilot.pause()
        screen.query_one(TextArea).text = "broken: [yaml"
        await pilot.pause()
        screen.action_save()
        await pilot.pause()

    assert roe_path.read_text() == original  # unchanged — save refused


def test_roe_wizard_writes_valid_yaml(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    out_path = str(tmp_path / "roe-wizard-out.yaml")
    answers = iter([
        "HTB Lame Test",        # engagement name
        "operator",             # operator
        "10.10.10.5",           # allowed IPs
        "*",                    # allowed techniques
        "n",                    # persistence
        "n",                    # evasion
        "n",                    # exfiltration
        "n",                    # kernel exploits
        "always_ask",           # hitl mode
        out_path,               # save path
    ])

    def fake_prompt(prompt_text, **kwargs):
        return next(answers)

    def fake_confirm(prompt_text, default=False):
        return next(answers) == "y"

    with patch("autored.cli.typer.prompt", side_effect=fake_prompt), \
         patch("autored.cli.typer.confirm", side_effect=fake_confirm):
        result = runner.invoke(app, ["roe-wizard"])

    assert result.exit_code == 0, result.output
    saved = Path(out_path).read_text()
    assert "HTB Lame Test" in saved
    # The wizard's output validates clean.
    from autored.config import validate_roe_yaml
    assert validate_roe_yaml(saved) == []


def test_app_action_opens_roe_editor(tmp_path, monkeypatch):
    """``r`` pushes RoEEditorScreen pointed at ``roe-sandbox.yaml``."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "roe-sandbox.yaml").write_text(VALID_ROE_YAML)
    import asyncio

    async def _run():
        app = AutoRedApp()
        async with app.run_test() as pilot:
            await pilot.press("r")
            await pilot.pause()
            return isinstance(app.screen, RoEEditorScreen)

    assert asyncio.run(_run())
