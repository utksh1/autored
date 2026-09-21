"""Engagement filesystem layout.

Each engagement is materialised on disk under ``engagements/<id>/``:

    engagements/
      <engagement_id>/
        manifest.json      # id, target, operator, started_at
        state.json         # latest serialised EngagementState snapshot
        state.db           # SQLite LangGraph checkpoints (Task 23 Step 5)
        raw/               # raw tool output (nmap XML, naabu JSONL, ...)
        evidence/          # screenshots, loot, exploit PoCs, ...

The functions here are deliberately side-effectful and path-based so the
CLI (Task 25) and resume command (Task 26) can call them directly.
"""

import json
from datetime import datetime
from pathlib import Path

from autored.logging import get_logger
from autored.state import EngagementState

log = get_logger("persistence.filesystem")

# Engagements live under ``./engagements`` relative to the current working
# directory. Tests monkeypatch.chdir into a tmp_path so they never pollute
# the real filesystem.
ENGAGEMENTS_DIR = Path("engagements")


def init_engagement_folder(engagement_id: str, target: str, operator: str) -> Path:
    """Create the engagement folder structure. Returns the folder path.

    Idempotent: calling it twice for the same id is safe. The manifest is
    (re)written on every call so the latest ``target``/``operator`` wins.
    """
    folder = ENGAGEMENTS_DIR / engagement_id
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "raw").mkdir(exist_ok=True)
    (folder / "evidence").mkdir(exist_ok=True)

    manifest = {
        "engagement_id": engagement_id,
        "target": target,
        "operator": operator,
        "started_at": datetime.utcnow().isoformat(),
    }
    (folder / "manifest.json").write_text(json.dumps(manifest, indent=2))
    log.info(
        "engagement_folder_init",
        engagement_id=engagement_id,
        path=str(folder),
    )
    return folder


def save_state_to_disk(engagement_id: str, state: EngagementState) -> None:
    """Serialize state to ``engagements/<id>/state.json``."""
    folder = ENGAGEMENTS_DIR / engagement_id
    folder.mkdir(parents=True, exist_ok=True)
    state_path = folder / "state.json"
    state_path.write_text(state.model_dump_json(indent=2))
    log.info("state_saved", engagement_id=engagement_id, path=str(state_path))


def load_state_from_disk(engagement_id: str) -> EngagementState | None:
    """Load state from ``engagements/<id>/state.json``.

    Returns ``None`` if the file does not exist or cannot be parsed — callers
    are expected to treat ``None`` as "no resumable state" and start fresh.
    """
    state_path = ENGAGEMENTS_DIR / engagement_id / "state.json"
    if not state_path.exists():
        return None
    try:
        return EngagementState.model_validate_json(state_path.read_text())
    except Exception as e:  # noqa: BLE001 — we want to swallow any deserialise error
        log.error("state_load_failed", engagement_id=engagement_id, error=str(e))
        return None


def list_engagements() -> list[dict]:
    """List all engagement folders with their manifest data.

    Each entry is ``{"id", "target", "operator", "started_at"}``. Folders
    without a manifest (or with a corrupt one) still appear, just with empty
    string fields, so they remain visible to the ``autored list`` command
    for manual cleanup.
    """
    if not ENGAGEMENTS_DIR.exists():
        return []
    engagements: list[dict] = []
    for folder in sorted(ENGAGEMENTS_DIR.iterdir()):
        if not folder.is_dir():
            continue
        manifest_path = folder / "manifest.json"
        entry: dict = {
            "id": folder.name,
            "target": "",
            "operator": "",
            "started_at": "",
        }
        if manifest_path.exists():
            try:
                manifest = json.loads(manifest_path.read_text())
                entry["target"] = manifest.get("target", "")
                entry["operator"] = manifest.get("operator", "")
                entry["started_at"] = manifest.get("started_at", "")
            except json.JSONDecodeError:
                log.warning("manifest_corrupt", engagement_id=folder.name)
        engagements.append(entry)
    return engagements
