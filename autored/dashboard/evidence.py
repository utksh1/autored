# autored/dashboard/evidence.py
"""Path-jailed evidence file viewer (spec §5).

Every request is resolved (symlinks included) against
``engagements/<id>/evidence/``; anything escaping the jail is a 400.
"""
from __future__ import annotations

import mimetypes
from pathlib import Path

from fastapi import HTTPException, Response

from autored.logging import get_logger

log = get_logger("dashboard.evidence")


def resolve_evidence_path(engagement_id: str, rel_path: str) -> Path:
    if engagement_id in ("", ".", "..") or "/" in engagement_id or "\\" in engagement_id:
        raise HTTPException(status_code=400, detail="invalid engagement id")
    jail = (Path("engagements") / engagement_id / "evidence").resolve()
    candidate = (jail / rel_path).resolve()
    if candidate != jail and jail not in candidate.parents:
        log.warning(
            "evidence_path_escape",
            engagement_id=engagement_id, path=rel_path,
            resolved=str(candidate),
        )
        raise HTTPException(status_code=400, detail="path escapes evidence jail")
    return candidate


async def serve_evidence(engagement_id: str, path: str) -> Response:
    try:
        target = resolve_evidence_path(engagement_id, path)
    except HTTPException:
        raise
    if not target.is_file():
        raise HTTPException(status_code=404, detail="evidence file not found")
    media_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
    return Response(content=target.read_bytes(), media_type=media_type)
