"""AutoRed engagement folder management.

Each engagement gets its own folder under ENGAGEMENTS_DIR:
    engagements/<id>/
        state.json       # serialized EngagementState (latest checkpoint)
        state.db         # LangGraph SqliteSaver checkpoint DB
        manifest.json    # engagement metadata
        raw/             # raw tool output
        evidence/        # exploit/post-ex evidence
        report.md
        report.pdf
        lessons.json
        audit.jsonl
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from autored.logging import get_logger

log = get_logger("persistence.filesystem")

ENGAGEMENTS_DIR = Path("engagements")


def init_engagement_folder(
    engagement_id: str, target: str, operator: str
) -> Path:
    """Create the engagement folder + raw/ + evidence/ + manifest.json."""
    p = ENGAGEMENTS_DIR / engagement_id
    (p / "raw").mkdir(parents=True, exist_ok=True)
    (p / "evidence").mkdir(parents=True, exist_ok=True)
    manifest = {
        "engagement_id": engagement_id,
        "target": target,
        "operator": operator,
        "started_at": datetime.utcnow().isoformat() + "Z",
    }
    (p / "manifest.json").write_text(json.dumps(manifest, indent=2))
    log.info("engagement_folder_init", engagement_id=engagement_id, path=str(p))
    return p


def save_state_to_disk(engagement_id: str, state) -> None:
    """Serialize EngagementState to engagements/<id>/state.json."""
    p = ENGAGEMENTS_DIR / engagement_id / "state.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(state.model_dump_json(indent=2))
    log.info("state_saved", engagement_id=engagement_id, path=str(p))


def load_state_from_disk(engagement_id: str):
    """Load EngagementState from disk. Returns None if missing or invalid."""
    from autored.state import EngagementState  # avoid circular import

    p = ENGAGEMENTS_DIR / engagement_id / "state.json"
    if not p.exists():
        return None
    try:
        return EngagementState.model_validate_json(p.read_text())
    except Exception as exc:
        log.error("state_load_failed", engagement_id=engagement_id, error=str(exc))
        return None


def list_engagements() -> list[dict]:
    """Scan ENGAGEMENTS_DIR for engagement folders, return manifest dicts."""
    out = []
    if not ENGAGEMENTS_DIR.exists():
        return out
    for d in sorted(ENGAGEMENTS_DIR.iterdir()):
        if not d.is_dir():
            continue
        manifest = d / "manifest.json"
        if not manifest.exists():
            continue
        try:
            out.append(json.loads(manifest.read_text()))
        except Exception as exc:
            log.warning("manifest_load_failed", path=str(manifest), error=str(exc))
    return out
