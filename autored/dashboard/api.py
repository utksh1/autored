"""Dashboard REST endpoints (spec §5).

Engagement list mirrors the CLI's ``engagements`` command: SQLite
(``db/engagements.sqlite``) first, filesystem scan fallback. State and
RoE come from ``engagements/<id>/state.json``.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Response

from autored.dashboard.bridge import DashboardBridge
from autored.logging import get_logger

log = get_logger("dashboard.api")

STATE_SUMMARY_FIELDS: tuple[str, ...] = (
    "phase", "engagement_id", "target_scope", "hosts", "services",
    "findings", "footholds", "harvested_secrets", "pivots",
    "movement_paths", "sub_engagements", "cleanup_results",
    "attack_hypotheses",
)
# WS frames cap large lists at this length; full rows come from GET /state
WS_LIST_CAP = 200


def state_summary(state, ws_mode: bool = False) -> dict[str, Any]:
    """Project an EngagementState to the display dict (spec §4).

    ``ws_mode=True`` caps long lists at ``WS_LIST_CAP`` entries (counts-only
    rule applies only to WS frames — GET /state always returns full rows).
    """
    summary: dict[str, Any] = {}
    for field in STATE_SUMMARY_FIELDS:
        value = getattr(state, field, [])
        if ws_mode and isinstance(value, list) and len(value) > WS_LIST_CAP:
            summary[field] = {"count": len(value)}
        else:
            summary[field] = value
    summary["pending_hitl_gates"] = []  # bridge injects the live list (Task 4)
    return summary


def _engagement_root() -> Path:
    return Path("engagements")


def _load_state(engagement_id: str):
    from autored.persistence.filesystem import load_state_from_disk

    return load_state_from_disk(engagement_id)


def create_app(bridges: dict[str, DashboardBridge] | None = None) -> FastAPI:
    bridges = bridges if bridges is not None else {}
    app = FastAPI(title="AutoRed Dashboard", docs_url=None, redoc_url=None)
    app.state.bridges = bridges

    from autored.dashboard.ws import router as ws_router

    app.include_router(ws_router)

    @app.post("/api/engagements/{engagement_id}/hitl/{gate_id}")
    async def resolve_hitl(engagement_id: str, gate_id: str, body: dict):
        approved = body.get("approved")
        if not isinstance(approved, bool):
            raise HTTPException(status_code=422, detail="approved must be a boolean")
        bridge = bridges.get(engagement_id)
        if bridge is None:
            raise HTTPException(
                status_code=404, detail="no live dashboard bridge for this engagement"
            )
        try:
            return await bridge.resolve_gate(gate_id, approved, body.get("note"))
        except ValueError as e:
            raise HTTPException(status_code=409, detail=str(e)) from e
        except KeyError as e:
            raise HTTPException(status_code=409, detail=str(e)) from e

    @app.get("/api/engagements")
    async def list_engagements() -> list[dict[str, Any]]:
        try:
            from autored.persistence.engagement_db import (
                init_db,
                list_engagements_with_findings,
            )

            db_path = "db/engagements.sqlite"

            async def _rows():
                await init_db(db_path)
                return await list_engagements_with_findings(db_path)

            rows = await _rows()
        except Exception as e:  # noqa: BLE001 — filesystem fallback (spec §14.2)
            log.info("dashboard_list_sqlite_unavailable", error=str(e))
            rows = None
        if rows:
            return [
                {
                    "engagement_id": r.get("id", ""),
                    "target": r.get("target", ""),
                    "phase": r.get("phase", "unknown"),
                    "started_at": r.get("start_ts", ""),
                    "operator": r.get("operator", ""),
                }
                for r in rows
            ]
        from autored.persistence.filesystem import list_engagements as fs_list

        return [
            {
                "engagement_id": r.get("id", r.get("engagement_id", "")),
                "target": r.get("target", ""),
                "phase": r.get("phase", "unknown"),
                "started_at": r.get("started_at", ""),
                "operator": r.get("operator", ""),
            }
            for r in fs_list()
        ]

    @app.get("/api/engagements/{engagement_id}/state")
    async def engagement_state(engagement_id: str) -> dict[str, Any]:
        state = _load_state(engagement_id)
        if state is None:
            raise HTTPException(status_code=404, detail=f"unknown engagement {engagement_id}")
        return state_summary(state)

    @app.get("/api/engagements/{engagement_id}/roe")
    async def engagement_roe(engagement_id: str) -> dict[str, Any]:
        state = _load_state(engagement_id)
        if state is None:
            raise HTTPException(status_code=404, detail=f"unknown engagement {engagement_id}")
        return state.rules_of_engagement.model_dump()

    from autored.dashboard.evidence import serve_evidence

    @app.get("/api/engagements/{engagement_id}/evidence/{path:path}")
    async def evidence(engagement_id: str, path: str) -> Response:
        return await serve_evidence(engagement_id, path)

    return app
