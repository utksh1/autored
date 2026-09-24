"""EvidenceViewerScreen + LogViewerScreen tests (Phase 6 Task 14).

Spec §17.5: evidence viewer renders one tab per file under
``engagements/<id>/evidence/``; log viewer tails ``logs/<date>.jsonl``
on a 1-second interval with a ``f`` follow-toggle binding.

Phase 6 Task 14 adaptation notes:

- The plan was authored against Textual 0.79's ``TabbedContentItem``
  widget, which was renamed to ``TabPane`` in Textual 0.86 (and carried
  through 8.x — the installed runtime). Tests query ``TabPane`` instead
  of ``TabbedContentItem`` to match the installed API.

- ``RichLog.line_count`` was removed when Textual switched to a
  ``list[Strip]`` backing store; the actual counter is now
  ``len(RichLog.lines)``. The log-viewer test uses that accessor
  rather than the removed property.

- The empty-evidence-dir test was rewritten to query for the actual
  ``#evidence-empty`` Static message rather than ``query_one(TabbedContent)``
  (which would raise ``NoMatches`` when the screen yields only the
  message widget).
"""
from datetime import datetime
from pathlib import Path

from textual.widgets import RichLog, Static, TabbedContent
from textual.widgets._tabbed_content import TabPane

from autored.models.roe import RulesOfEngagement
from autored.state import EngagementState
from autored.tui.app import AutoRedApp
from autored.tui.screens.evidence_viewer import EvidenceViewerScreen
from autored.tui.screens.log_viewer import LogViewerScreen


def _roe() -> RulesOfEngagement:
    return RulesOfEngagement(
        engagement_name="t", operator="t", operator_signature="t",
        allowed_ips=["*"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, data_destruction_allowed=False,
        kernel_exploits_allowed=True, hitl_mode="auto_approve",
    )


def _seed_evidence(tmp_path: Path, engagement_id: str) -> None:
    ev_dir = tmp_path / "engagements" / engagement_id / "evidence"
    ev_dir.mkdir(parents=True)
    (ev_dir / "shell_session_001.txt").write_text(
        "whoami\nnt authority\\system\nipconfig\n"
    )
    (ev_dir / "screenshot_001.png").write_bytes(b"\x89PNG fake image bytes")


async def test_evidence_viewer_renders_text_and_png_tabs(tmp_path, monkeypatch):
    """One ``TabPane`` per evidence file (sorted: png, txt alphabetically)."""
    monkeypatch.chdir(tmp_path)
    _seed_evidence(tmp_path, "ev-e1")

    app = AutoRedApp(engagement_id="ev-e1")
    app.current_state = EngagementState(
        engagement_id="ev-e1", target_scope=["10.0.0.5"],
        operator="t", rules_of_engagement=_roe(),
    )
    async with app.run_test() as pilot:
        await pilot.press("v")
        await pilot.pause()
        assert isinstance(app.screen, EvidenceViewerScreen)
        tabs = app.screen.query_one(TabbedContent)
        # ``TabPane`` (Textual ≥0.86) replaces the older
        # ``TabbedContentItem`` from Textual 0.79 — same intent, renamed
        # for the installed runtime.
        pane_count = len(tabs.query(TabPane))
        assert pane_count == 2  # one tab per evidence file


async def test_evidence_viewer_empty_dir_shows_message(tmp_path, monkeypatch):
    """Empty evidence dir → explicit message Static (no tabs)."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "engagements" / "ev-empty" / "evidence").mkdir(parents=True)

    app = AutoRedApp(engagement_id="ev-empty")
    async with app.run_test() as pilot:
        await pilot.press("v")
        await pilot.pause()
        assert isinstance(app.screen, EvidenceViewerScreen)
        # The empty-dir screen yields only the ``#evidence-empty`` Static
        # (no ``TabbedContent``); the plan's ``query_one(TabbedContent)``
        # would raise ``NoMatches`` — query the actual message widget.
        message = app.screen.query_one("#evidence-empty", Static)
        assert message is not None
        # ``Static.content`` is the rendered Visual (str when constructed
        # from a string) — ``renderable`` was the older Textual 0.79
        # attribute, removed in 8.x.
        assert "ev-empty" in str(message.content)


async def test_evidence_viewer_requires_engagement(tmp_path, monkeypatch):
    """Pressing ``v`` with no engagement notifies instead of crashing."""
    monkeypatch.chdir(tmp_path)
    app = AutoRedApp()  # no engagement — list screen mounts
    async with app.run_test() as pilot:
        await pilot.press("v")
        await pilot.pause()
        assert not isinstance(app.screen, EvidenceViewerScreen)


async def test_log_viewer_tails_today_log(tmp_path, monkeypatch):
    """``on_mount`` seeds today's log immediately (1s interval continues live)."""
    monkeypatch.chdir(tmp_path)
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    today = datetime.utcnow().strftime("%Y-%m-%d")
    (log_dir / f"{today}.jsonl").write_text(
        '{"event": "nmap_start", "target": "10.0.0.5"}\n'
        '{"event": "nmap_done", "hosts": 1}\n'
    )

    app = AutoRedApp()
    async with app.run_test() as pilot:
        await pilot.press("l")
        await pilot.pause()
        assert isinstance(app.screen, LogViewerScreen)
        log_widget = app.screen.query_one(RichLog)
        # ``RichLog.line_count`` was removed in Textual ≥0.86 (the
        # backing store is now ``list[Strip]``). ``len(lines)`` is the
        # documented accessor; both JSONL lines render on the initial
        # ``_refresh()`` call inside ``on_mount``.
        assert len(log_widget.lines) >= 2  # both JSONL lines rendered


async def test_log_viewer_missing_log_shows_message(tmp_path, monkeypatch):
    """Missing log dir → "no operational log yet" hint, no crash."""
    monkeypatch.chdir(tmp_path)
    app = AutoRedApp()
    async with app.run_test() as pilot:
        await pilot.press("l")
        await pilot.pause()
        assert isinstance(app.screen, LogViewerScreen)  # mounted, no crash
        log_widget = app.screen.query_one(RichLog)
        # The "no log yet" hint was written once on the initial refresh
        # (``_rendered_lines == 0`` branch in ``_refresh``).
        assert len(log_widget.lines) >= 1
