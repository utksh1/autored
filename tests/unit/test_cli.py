"""Tests for the AutoRed Typer CLI (Phase 1 + Phase 6).

Covers the original Phase 1 commands (``run``, ``resume``,
``engagements``, ``version``, ``roe-wizard``) plus the Phase 6
reporting / inspection commands (``report``, ``state``, full
``resume``, SQLite-backed ``engagements``). We assert against
``--help`` output, the stubbed commands, and (for Phase 6) the
new commands' end-to-end happy paths with mocks. The ``run`` command
itself is an end-to-end LangGraph invocation covered by integration
tests, not by unit assertions here.
"""

from __future__ import annotations

from typer.testing import CliRunner

from autored.cli import app

runner = CliRunner()


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
    assert "v0.1.0" in result.stdout
    assert "Phase 1" in result.stdout


def test_engagements_command_empty(tmp_path, monkeypatch):
    """`engagements` with no engagements dir should print an empty table."""
    # chdir to tmp_path so the SQLite ``db/engagements.sqlite`` init
    # (Phase 6 SQLite-backed engagements list) doesn't create ``db/``
    # as a side effect in the repo root.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("autored.persistence.filesystem.ENGAGEMENTS_DIR", tmp_path / "engagements")
    result = runner.invoke(app, ["engagements"])
    assert result.exit_code == 0
    assert "Engagements" in result.stdout


def test_resume_command_missing_state(tmp_path, monkeypatch):
    """`resume` on a non-existent engagement should exit 1 cleanly."""
    monkeypatch.setattr("autored.persistence.filesystem.ENGAGEMENTS_DIR", tmp_path / "engagements")
    result = runner.invoke(app, ["resume", "does-not-exist-001"])
    assert result.exit_code == 1
    assert "No state found" in result.stdout


def test_roe_wizard_writes_valid_yaml(tmp_path, monkeypatch):
    """`roe-wizard` runs the full §8.3 flow and writes a valid RoE file.

    Patches ``typer.prompt`` / ``typer.confirm`` so the wizard runs
    end-to-end without stdin; asserts the saved YAML parses cleanly
    through ``validate_roe_yaml`` (the same validator the RoE editor
    screen uses).
    """
    from unittest.mock import patch
    from autored.config import validate_roe_yaml

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
    assert validate_roe_yaml(saved) == []


# --- Phase 6 (Task 11): report / state / resume / engagements ------------- #

import json  # noqa: E402 — local-style grouping for Phase 6 block
from pathlib import Path  # noqa: E402
from unittest.mock import AsyncMock, MagicMock, patch  # noqa: E402


def _write_state_file(tmp_path, engagement_id: str, phase: str = "postex") -> None:
    """Drop a minimal saved state on disk exactly like save_state_to_disk."""
    from autored.models.roe import RulesOfEngagement
    from autored.state import EngagementState

    roe = RulesOfEngagement(
        engagement_name="t", operator="t", operator_signature="t",
        allowed_ips=["*"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, data_destruction_allowed=False,
        kernel_exploits_allowed=True, hitl_mode="auto_approve",
    )
    state = EngagementState(
        engagement_id=engagement_id, target_scope=["10.0.0.5"],
        operator="t", rules_of_engagement=roe, phase=phase,
    )
    eng_dir = tmp_path / "engagements" / engagement_id
    eng_dir.mkdir(parents=True)
    (eng_dir / "state.json").write_text(state.model_dump_json())


def test_report_command_missing_state_exits_1(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["report", "no-such-engagement"])
    assert result.exit_code == 1
    assert "No state found" in result.output


def test_report_command_runs_pipeline_and_prints_paths(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_state_file(tmp_path, "cli-rep-e1", phase="cleanup")

    from autored.models.report import ReportPaths

    fake_result = {
        "phase": "done",
        "summary": "1 foothold",
        "lessons": [],
        "mitre_mappings": [],
        "report_paths": ReportPaths(
            markdown_path=str(tmp_path / "engagements/cli-rep-e1/report.md"),
            pdf_path=None,
            lessons_path=str(tmp_path / "engagements/cli-rep-e1/lessons.json"),
        ),
        "iteration_count": 1,
    }
    (tmp_path / "engagements/cli-rep-e1/report.md").write_text("# Report")
    (tmp_path / "engagements/cli-rep-e1/lessons.json").write_text("[]")

    with patch("autored.agents.report.report_node",
               AsyncMock(return_value=fake_result)):
        result = runner.invoke(app, ["report", "cli-rep-e1"])

    assert result.exit_code == 0
    assert "report.md" in result.output
    # The merged state was persisted back to disk with phase=done.
    saved = json.loads(
        (tmp_path / "engagements/cli-rep-e1/state.json").read_text())
    assert saved["phase"] == "done"


def test_state_command_prints_counts(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_state_file(tmp_path, "cli-st-e1", phase="lateral")
    result = runner.invoke(app, ["state", "cli-st-e1"])
    assert result.exit_code == 0
    assert "cli-st-e1" in result.output
    assert "Phase" in result.output


def test_state_command_missing_state_exits_1(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["state", "ghost"])
    assert result.exit_code == 1


def test_resume_command_checkpoint_path(tmp_path, monkeypatch):
    """Resume prefers LangGraph checkpoint continuation."""
    monkeypatch.chdir(tmp_path)
    _write_state_file(tmp_path, "cli-res-e1", phase="exploit")

    fake_graph = MagicMock()
    fake_graph.ainvoke = AsyncMock(return_value={"phase": "done"})
    fake_checkpointer = MagicMock()

    async def fake_make_checkpointer(engagement_id):
        return fake_checkpointer

    # NOTE: the resume command imports build_phase6_graph / make_checkpointer
    # inside the function body, so patches must target the SOURCE modules
    # (patching autored.cli.* would raise AttributeError — those attributes
    # never exist at module level).
    with patch("autored.graph.build_phase6_graph", return_value=fake_graph), \
         patch("autored.persistence.sqlite_saver.make_checkpointer",
               fake_make_checkpointer):
        result = runner.invoke(app, ["resume", "cli-res-e1"])

    assert result.exit_code == 0
    # Checkpoint resume = ainvoke(None, config with thread_id)
    call_args = fake_graph.ainvoke.await_args
    assert call_args.args[0] is None
    assert call_args.kwargs["config"]["configurable"]["thread_id"] == "cli-res-e1"


def test_resume_command_falls_back_to_saved_state(tmp_path, monkeypatch):
    """No checkpoint history → re-invoke with the loaded state."""
    monkeypatch.chdir(tmp_path)
    _write_state_file(tmp_path, "cli-res-e2", phase="exploit")

    fake_graph = MagicMock()

    async def _first_none_then_state(*args, **kwargs):
        if args and args[0] is None:
            raise RuntimeError("no checkpoint history")
        return {"phase": "done"}

    fake_graph.ainvoke = AsyncMock(side_effect=_first_none_then_state)

    async def fake_make_checkpointer(engagement_id):
        return MagicMock()

    # Function-local imports → patch the SOURCE modules (see note above).
    with patch("autored.graph.build_phase6_graph", return_value=fake_graph), \
         patch("autored.persistence.sqlite_saver.make_checkpointer",
               fake_make_checkpointer):
        result = runner.invoke(app, ["resume", "cli-res-e2"])

    assert result.exit_code == 0
    assert fake_graph.ainvoke.await_count == 2  # None first, then the state


def test_engagements_command_prefers_sqlite(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    async def fake_list(db_path):
        return [{
            "id": "db-e1", "target": "10.0.0.5", "phase": "done",
            "start_ts": "2026-09-22T10:00:00", "operator": "t",
            "summary": "x", "report_path": None, "end_ts": None,
            "parent_engagement_id": None,
        }]

    async def fake_init(db_path):
        return None

    # Function-local imports → patch the SOURCE modules.
    with patch("autored.persistence.engagement_db.init_db", fake_init), \
         patch("autored.persistence.engagement_db.list_engagements_with_findings",
               fake_list):
        result = runner.invoke(app, ["engagements"])

    assert result.exit_code == 0
    assert "db-e1" in result.output


def test_engagements_command_falls_back_to_filesystem(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    async def boom(db_path):
        raise RuntimeError("no db")

    def fake_fs_list():
        return [{"id": "fs-e1", "target": "10.0.0.9", "operator": "t",
                 "started_at": "2026-09-22"}]

    # Function-local imports → patch the SOURCE modules.
    with patch("autored.persistence.engagement_db.init_db",
               AsyncMock(side_effect=boom)), \
         patch("autored.persistence.filesystem.list_engagements", fake_fs_list):
        result = runner.invoke(app, ["engagements"])

    assert result.exit_code == 0
    assert "fs-e1" in result.output
