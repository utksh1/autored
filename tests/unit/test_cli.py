"""Unit tests for the AutoRed CLI (Tasks 25-27).

These tests use Typer's ``CliRunner`` so no real engagement is started —
they only exercise argument parsing, help text, and the pure-Python
``engagements`` / ``resume`` / ``roe-wizard`` commands.
"""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from autored.cli import app


runner = CliRunner()


# --- Task 25: CLI help & run-command help ------------------------------


def test_cli_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "AutoRed" in result.stdout


def test_run_command_help():
    result = runner.invoke(app, ["run", "--help"])
    assert result.exit_code == 0
    assert "--target" in result.stdout
    assert "--roe" in result.stdout
    assert "--no-tui" in result.stdout


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "AutoRed" in result.stdout
    assert "Phase 1" in result.stdout
    assert "v0.1.0" in result.stdout


# --- Task 26: engagements & resume -------------------------------------


def test_engagements_empty(tmp_path, monkeypatch):
    """With no engagements folder, the command should still exit 0."""
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["engagements"])
    assert result.exit_code == 0
    # Rich renders the table title even when empty
    assert "Engagements" in result.stdout


def test_engagements_lists_existing(tmp_path, monkeypatch):
    """If a manifest exists on disk, it should appear in the table."""
    monkeypatch.chdir(tmp_path)
    eng_dir = tmp_path / "engagements" / "test-eng-001"
    eng_dir.mkdir(parents=True)
    (eng_dir / "manifest.json").write_text(
        json.dumps(
            {
                "engagement_id": "test-eng-001",
                "target": "10.10.10.5",
                "operator": "test",
                "started_at": "2026-09-21T12:00:00",
            }
        )
    )
    result = runner.invoke(app, ["engagements"])
    assert result.exit_code == 0
    assert "test-eng-001" in result.stdout
    assert "10.10.10.5" in result.stdout


def test_resume_loads_state_from_disk(tmp_path, monkeypatch):
    """Resume should read state.json and print the last phase & iteration."""
    monkeypatch.chdir(tmp_path)
    eng_dir = tmp_path / "engagements" / "test-eng-001"
    eng_dir.mkdir(parents=True)
    (eng_dir / "manifest.json").write_text(
        json.dumps(
            {
                "engagement_id": "test-eng-001",
                "target": "10.10.10.5",
                "operator": "test",
                "started_at": "2026-09-21T12:00:00",
            }
        )
    )
    state_payload = {
        "engagement_id": "test-eng-001",
        "target_scope": ["10.10.10.5"],
        "operator": "test",
        "rules_of_engagement": {
            "engagement_name": "t",
            "operator": "o",
            "operator_signature": "s",
            "allowed_ips": ["0.0.0.0/0"],
            "allowed_techniques": ["*"],
            "persistence_allowed": True,
            "evasion_allowed": True,
            "exfiltration_allowed": True,
            "data_destruction_allowed": False,
            "kernel_exploits_allowed": True,
            "hitl_mode": "auto_approve",
        },
        "phase": "recon",
        "iteration_count": 3,
    }
    (eng_dir / "state.json").write_text(json.dumps(state_payload))

    result = runner.invoke(app, ["resume", "test-eng-001"])
    assert result.exit_code == 0
    assert "test-eng-001" in result.stdout
    assert "recon" in result.stdout
    assert "3" in result.stdout


def test_resume_missing_engagement(tmp_path, monkeypatch):
    """Resume should exit non-zero if no state file exists."""
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["resume", "does-not-exist"])
    assert result.exit_code != 0


# --- Task 27: roe-wizard stub ------------------------------------------


def test_roe_wizard_stub():
    result = runner.invoke(app, ["roe-wizard"])
    assert result.exit_code == 0
    assert "sandbox" in result.stdout.lower()
