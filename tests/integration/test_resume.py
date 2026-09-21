"""Integration tests for engagement persistence (Task 23).

Verifies:
  * ``init_engagement_folder`` creates the expected folder layout + manifest.
  * ``save_state_to_disk`` / ``load_state_from_disk`` round-trip an
    ``EngagementState``.
  * ``list_engagements`` enumerates existing engagement folders.
  * ``make_checkpointer`` produces a working ``AsyncSqliteSaver`` whose
    underlying SQLite DB lives inside the engagement folder.
"""

import json

import pytest
from pathlib import Path

from autored.persistence.filesystem import (
    init_engagement_folder,
    save_state_to_disk,
    load_state_from_disk,
    list_engagements,
)
from autored.persistence.sqlite_saver import make_checkpointer
from autored.state import EngagementState
from autored.models.roe import RulesOfEngagement


@pytest.mark.asyncio
async def test_engagement_folder_lifecycle(tmp_path, monkeypatch, sandbox_roe_yaml):
    monkeypatch.chdir(tmp_path)

    roe = RulesOfEngagement.model_validate_yaml(sandbox_roe_yaml)
    state = EngagementState(
        engagement_id="test-eng-001",
        target_scope=["10.10.10.5"],
        operator="test",
        rules_of_engagement=roe,
    )

    # Init folder
    folder = init_engagement_folder(state.engagement_id, "10.10.10.5", "test")
    assert folder.exists()
    assert (folder / "raw").exists()
    assert (folder / "evidence").exists()
    assert (folder / "manifest.json").exists()
    manifest = json.loads((folder / "manifest.json").read_text())
    assert manifest["engagement_id"] == "test-eng-001"
    assert manifest["target"] == "10.10.10.5"
    assert manifest["operator"] == "test"

    # Save state
    save_state_to_disk(state.engagement_id, state)
    assert (folder / "state.json").exists()

    # Load state
    loaded = load_state_from_disk(state.engagement_id)
    assert loaded is not None
    assert loaded.engagement_id == "test-eng-001"
    assert loaded.target_scope == ["10.10.10.5"]

    # Loading a missing engagement returns None
    missing = load_state_from_disk("does-not-exist")
    assert missing is None


def test_list_engagements(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # Create some fake engagement folders
    for eid in ["2026-09-21_001-foo", "2026-09-21_002-bar"]:
        folder = Path("engagements") / eid
        folder.mkdir(parents=True)
        (folder / "manifest.json").write_text(json.dumps({
            "engagement_id": eid,
            "target": "10.10.10.5",
            "operator": "test",
            "started_at": "2026-09-21T00:00:00",
        }))

    engagements = list_engagements()
    assert len(engagements) == 2
    ids = {e["id"] for e in engagements}
    assert ids == {"2026-09-21_001-foo", "2026-09-21_002-bar"}
    # Each entry should expose manifest fields
    for entry in engagements:
        assert "target" in entry
        assert "operator" in entry
        assert "started_at" in entry


@pytest.mark.asyncio
async def test_make_checkpointer_creates_db(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # Need an engagement folder for the DB to live inside
    init_engagement_folder("2026-09-21_001-lame-10.10.10.5", "10.10.10.5", "test")

    checkpointer = await make_checkpointer("2026-09-21_001-lame-10.10.10.5")
    try:
        # The SQLite DB file should exist inside the engagement folder
        db_path = Path("engagements") / "2026-09-21_001-lame-10.10.10.5" / "state.db"
        assert db_path.exists()

        # Sanity-check the checkpointer behaves like a BaseCheckpointSaver
        from langgraph.checkpoint.base import BaseCheckpointSaver

        assert isinstance(checkpointer, BaseCheckpointSaver)
    finally:
        # Close the underlying aiosqlite connection so the event loop
        # can tear down cleanly (unclosed connections make pytest hang).
        await checkpointer.conn.close()
