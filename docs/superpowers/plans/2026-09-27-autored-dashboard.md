# AutoRed Dashboard (Live Ops Console) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a browser-based live ops console: `autored run --dashboard` serves a React SPA on `127.0.0.1:8500` that shows the kill chain live and resolves HitL gates, per spec `docs/superpowers/specs/2026-09-27-dashboard-liveops-design.md`.

**Architecture:** A `autored/dashboard/` package — FastAPI app + `DashboardBridge` that taps the existing `EventBus` (drains `orchestrator_to_tui`, fans out over WebSocket, resolves gates by emitting `{"response": "approve"|"reject"}` to `tui_to_orchestrator`) — serving a Vite-built React SPA from `frontend/dist/`. No changes to the orchestrator, agents, RoE Guard, or models.

**Tech Stack:** Python 3.12, `fastapi==0.115.6`, `uvicorn==0.32.1`, httpx (test client, already a dep via test stack), Vite 5 + React 18 + TypeScript 5 + `@xyflow/react` (react-flow v12) + vitest 2.

## Global Constraints

- **Orchestrator contract is frozen.** `EventBus` (autored/tui/event_bus.py) exposes exactly: `async emit_to_tui(dict)`, `async emit_to_orchestrator(dict)`, `async wait_for_tui_response() -> dict`, `try_get_tui_event() -> dict | None`. The bridge consumes these; never edit the bus.
- **HitL response shape** consumed by agents (autored/agents/exploit.py:210-218): `response.get("response")` ∈ `"approve"|"edit"|"reject"|"skip"|"abort"`. The dashboard emits exactly `{"response": "approve"}` or `{"response": "reject"}` — NOT `{"approved": true}`.
- **Gate events carry no ID.** Nodes emit `{"type": "hitl_gate", "gate_type": ..., "target": ..., "command": ..., "risks": [...], ...}` (fields vary per agent). The bridge assigns `gate_id = str(seq)` when draining.
- **Single-frontend constraint:** `--tui` and `--dashboard` are mutually exclusive; both drain `orchestrator_to_tui`. CLI must reject the combination.
- **Localhost only:** bind `127.0.0.1`, default port `8500` (`--dashboard-port` overrides). No auth.
- **Secret redaction:** secret values may appear only in `state` frames (Secrets tab). Every `event` frame is scrubbed against known secret values → `[REDACTED]`.
- **Ring buffer:** last 500 events replayed on WS connect, carrying original `seq`.
- **Server isolation:** a dashboard-server crash must never abort the orchestrator run.
- Code style: `ruff` line-length=100, Python 3.12; conventional commits.
- Frontend: plain CSS modules (no Tailwind), `react-router` v6, `useReducer`+context (no state libs), `frontend/dist/` and `node_modules/` gitignored.
- Test commands run from repo root with `uv run pytest ...` (backend) and `npm --prefix frontend run test` (frontend).

## File Structure

```
autored/dashboard/
├── __init__.py            # Task 2 (exports create_app, DashboardBridge)
├── api.py                 # Task 2: REST endpoints (list, state, roe)
├── evidence.py            # Task 3: path-jailed evidence endpoint
├── bridge.py              # Task 4-5: EventBus tap, ring buffer, gate registry
└── ws.py                  # Task 5: WS endpoint + HitL POST endpoint
autored/cli.py             # Task 1 (--tui --dashboard reject), Task 6 (--dashboard wiring)
tests/unit/dashboard/
├── test_api.py            # Task 2-3
├── test_bridge.py         # Task 4
└── test_hitl_ws.py        # Task 5 (+ Task 6 crash-isolation)
frontend/
├── package.json  vite.config.ts  tsconfig.json  index.html
└── src/
    ├── main.tsx  App.tsx  api.ts  socket.ts  types.ts
    ├── views/EngagementList.tsx  views/EngagementDetail.tsx
    └── components/PhaseTimeline.tsx  ActivityLog.tsx  DataPanels.tsx
        StateInspector.tsx  RoeCard.tsx  HitLModal.tsx  AttackGraph.tsx
tests/unit/dashboard/test_cli_dashboard.py   # Task 1, 6
```

---

### Task 1: Dependencies + CLI Flag + Mutual-Exclusion Rejection

**Files:**
- Modify: `pyproject.toml` (dependencies array)
- Modify: `autored/cli.py` (run signature + guard, near lines 71-81)
- Test: `tests/unit/dashboard/test_cli_dashboard.py` (NEW)

**Interfaces:**
- Produces: `run(target, roe, name, tui, dashboard, dashboard_port)` — Tasks 6 wires the body; this task only adds the options and the rejection guard.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/dashboard/test_cli_dashboard.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/dashboard/test_cli_dashboard.py -v`
Expected: FAIL — `--dashboard` is an unknown option (`exit_code == 2` in test 2, and test 1 fails because the flag doesn't exist to even trigger rejection).

- [ ] **Step 3: Implement — add deps and CLI options**

In `pyproject.toml` dependencies array (keep alphabetical order if the list is sorted):

```toml
    "fastapi==0.115.6",
    "uvicorn==0.32.1",
```

Then `uv sync` to update the lockfile.

In `autored/cli.py`, extend the `run` signature (after the `tui` option):

```python
    dashboard: bool = typer.Option(
        False,
        "--dashboard/--no-dashboard",
        help="Serve the browser dashboard on 127.0.0.1 during the run.",
    ),
    dashboard_port: int = typer.Option(
        8500,
        "--dashboard-port",
        help="Port for the dashboard server.",
    ),
```

And immediately after the docstring, before `load_roe`:

```python
    if tui and dashboard:
        console.print(
            "[bold red]--tui and --dashboard are mutually exclusive:[/] both "
            "consume the same EventBus queue; pick one operator frontend."
        )
        raise typer.Exit(code=1)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/dashboard/test_cli_dashboard.py -v`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml uv.lock autored/cli.py tests/unit/dashboard/test_cli_dashboard.py
git commit -m "feat: add --dashboard flag with --tui mutual exclusion"
```

---

### Task 2: FastAPI Server + Engagement List / State / RoE Endpoints

**Files:**
- Create: `autored/dashboard/__init__.py`, `autored/dashboard/api.py`
- Test: `tests/unit/dashboard/test_api.py` (NEW)

**Interfaces:**
- Consumes: `autored.persistence.filesystem.list_engagements() -> list[dict]`, `load_state_from_disk(engagement_id) -> EngagementState | None`, `autored.persistence.engagement_db.init_db(db_path)`, `list_engagements_with_findings(db_path) -> list[dict]`, `autored.state.EngagementState`.
- Produces: `create_app() -> fastapi.FastAPI` (mounted routes listed below; Task 5 adds WS + HitL routes, Task 10 adds StaticFiles). Helper `state_summary(state: EngagementState) -> dict` and `STATE_SUMMARY_FIELDS` — reused by the bridge in Task 4.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/dashboard/test_api.py
"""Dashboard REST API tests (engagements, state, roe)."""
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from autored.models.roe import RulesOfEngagement
from autored.state import EngagementState


@pytest.fixture()
def engagement_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """One engagement on disk under a temp root the API reads from."""
    monkeypatch.chdir(tmp_path)
    eng = tmp_path / "engagements" / "eng_test_01"
    (eng / "evidence").mkdir(parents=True)
    roe = RulesOfEngagement(
        engagement_name="t", operator="op", operator_signature="s",
        allowed_ips=["0.0.0.0/0"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, kernel_exploits_allowed=True,
    )
    state = EngagementState(
        engagement_id="eng_test_01", target_scope=["10.0.0.1"],
        operator="op", rules_of_engagement=roe,
    )
    state.phase = "recon"
    (eng / "state.json").write_text(state.model_dump_json())
    (eng / "manifest.json").write_text(
        '{"engagement_id": "eng_test_01", "target": "10.0.0.1", '
        '"operator": "op", "started_at": "2026-09-27T00:00:00"}'
    )
    return eng


@pytest.fixture()
def client():
    from autored.dashboard.api import create_app

    return AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://test")


@pytest.mark.asyncio
async def test_engagement_list_from_filesystem(engagement_dir, client):
    # SQLite (db/engagements.sqlite) doesn't exist under tmp_path → fallback
    resp = await client.get("/api/engagements")
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 1
    assert rows[0]["engagement_id"] == "eng_test_01"
    assert rows[0]["target"] == "10.0.0.1"


@pytest.mark.asyncio
async def test_engagement_state_endpoint(engagement_dir, client):
    resp = await client.get("/api/engagements/eng_test_01/state")
    assert resp.status_code == 200
    body = resp.json()
    assert body["phase"] == "recon"
    assert "pending_hitl_gates" in body
    assert body["harvested_secrets"] == []


@pytest.mark.asyncio
async def test_state_unknown_engagement_404(engagement_dir, client):
    resp = await client.get("/api/engagements/eng_nope/state")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_roe_endpoint(engagement_dir, client):
    resp = await client.get("/api/engagements/eng_test_01/roe")
    assert resp.status_code == 200
    assert resp.json()["operator"] == "op"
    assert resp.json()["engagement_name"] == "t"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/dashboard/test_api.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'autored.dashboard'`.

- [ ] **Step 3: Implement the API module**

```python
# autored/dashboard/__init__.py
"""Browser dashboard (live ops console) — spec 2026-09-27-dashboard-liveops."""
from autored.dashboard.api import create_app, state_summary

__all__ = ["create_app", "state_summary"]
```

```python
# autored/dashboard/api.py
"""Dashboard REST endpoints (spec §5).

Engagement list mirrors the CLI's ``engagements`` command: SQLite
(``db/engagements.sqlite``) first, filesystem scan fallback. State and
RoE come from ``engagements/<id>/state.json``.
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException

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


def create_app() -> FastAPI:
    app = FastAPI(title="AutoRed Dashboard", docs_url=None, redoc_url=None)

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

    return app
```

Note: `load_state_from_disk` may raise or return `None` on a missing file — wrap accordingly if its contract differs on inspection (return `None` → 404 path above stays).

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/dashboard/test_api.py -v`
Expected: PASS (4 passed). Then `uv run pytest -q` → full suite green (new tests only added).

- [ ] **Step 5: Commit**

```bash
git add autored/dashboard/__init__.py autored/dashboard/api.py tests/unit/dashboard/test_api.py
git commit -m "feat: dashboard API with engagement list, state, and roe endpoints"
```

---

### Task 3: Evidence Endpoint with Path Jail

**Files:**
- Create: `autored/dashboard/evidence.py`
- Modify: `autored/dashboard/api.py` (include the evidence router in `create_app`)
- Test: `tests/unit/dashboard/test_api.py` (append)

**Interfaces:**
- Consumes: nothing new — filesystem only.
- Produces: `resolve_evidence_path(engagement_id: str, rel_path: str) -> Path` — raises `HTTPException(400)` on escape, `HTTPException(404)` on missing. Route `GET /api/engagements/{id}/evidence/{path:path}`.

- [ ] **Step 1: Write the failing tests (append to test_api.py)**

```python
@pytest.mark.asyncio
async def test_evidence_serves_file(engagement_dir, client):
    (engagement_dir / "evidence" / "nmap.txt").write_text("PORT STATE\n21 open")
    resp = await client.get("/api/engagements/eng_test_01/evidence/nmap.txt")
    assert resp.status_code == 200
    assert "21 open" in resp.text


@pytest.mark.asyncio
async def test_evidence_rejects_traversal(engagement_dir, client):
    resp = await client.get("/api/engagements/eng_test_01/evidence/../../state.json")
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_evidence_rejects_symlink_escape(engagement_dir, client):
    outside = engagement_dir.parent / "outside.txt"
    outside.write_text("secret")
    link = engagement_dir / "evidence" / "leak.txt"
    link.symlink_to(outside)
    resp = await client.get("/api/engagements/eng_test_01/evidence/leak.txt")
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_evidence_missing_file_404(engagement_dir, client):
    resp = await client.get("/api/engagements/eng_test_01/evidence/nope.txt")
    assert resp.status_code == 404
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/dashboard/test_api.py -k evidence -v`
Expected: FAIL — 404 on the valid file (route doesn't exist yet); the traversal test may 404 rather than 400 (also a fail: expected 400).

- [ ] **Step 3: Implement the evidence module + mount**

```python
# autored/dashboard/evidence.py
"""Path-jailed evidence file viewer (spec §5).

Every request is resolved (symlinks included) against
``engagements/<id>/evidence/``; anything escaping the jail is a 400.
"""
from __future__ import annotations

import mimetypes
from pathlib import Path

from fastapi import HTTPException, Response


def resolve_evidence_path(engagement_id: str, rel_path: str) -> Path:
    jail = (Path("engagements") / engagement_id / "evidence").resolve()
    candidate = (jail / rel_path).resolve()
    if candidate != jail and jail not in candidate.parents:
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
```

In `autored/dashboard/api.py`, inside `create_app()` add:

```python
        from autored.dashboard.evidence import serve_evidence

        @app.get("/api/engagements/{engagement_id}/evidence/{path:path}")
        async def evidence(engagement_id: str, path: str) -> Response:
            return await serve_evidence(engagement_id, path)
```

(Add `Response` to the fastapi import line.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/dashboard/test_api.py -v`
Expected: PASS (8 passed).

- [ ] **Step 5: Commit**

```bash
git add autored/dashboard/evidence.py autored/dashboard/api.py tests/unit/dashboard/test_api.py
git commit -m "feat: path-jailed evidence viewer endpoint"
```

---

### Task 4: DashboardBridge — EventBus Tap, Ring Buffer, Fan-Out, Scrubbing

**Files:**
- Create: `autored/dashboard/bridge.py`
- Modify: `autored/dashboard/__init__.py` (export `DashboardBridge`)
- Test: `tests/unit/dashboard/test_bridge.py` (NEW)

**Interfaces:**
- Consumes: `EventBus.try_get_tui_event()`, `load_state_from_disk`, `state_summary(state, ws_mode=True)` from Task 2.
- Produces (Task 5 and Task 6 consume these exact names):
  - `DashboardBridge(engagement_id: str, bus, max_history: int = 500)`
  - `async start() -> None` / `async stop() -> None` (drain loop task management, 0.1 s poll)
  - `register_client() -> asyncio.Queue` / `unregister_client(q: asyncio.Queue) -> None`
  - `hello_frames() -> list[dict]` — `[hello, *replayed events]`
  - `async resolve_gate(gate_id: str, approved: bool, note: str | None) -> dict` — raises `KeyError` (unknown), `ValueError` (already resolved); emits `{"response": "approve"|"reject"}` on the bus
  - `pending_gate_summaries() -> list[dict]` — `[{gate_id, gate_type, target, command, risks}]`
  - `async broadcast_state() -> None` — builds summary from `load_state_from_disk`, injects `pending_hitl_gates`, pushes `{"type": "state", ...}` to all clients

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/dashboard/test_bridge.py
"""DashboardBridge tests: drain, seq, ring buffer, scrubbing, gates."""
import asyncio
import json
from pathlib import Path

import pytest

from autored.dashboard.bridge import DashboardBridge
from autored.models.roe import RulesOfEngagement
from autored.state import EngagementState
from autored.tui.event_bus import EventBus


@pytest.fixture()
def roe() -> RulesOfEngagement:
    return RulesOfEngagement(
        engagement_name="t", operator="op", operator_signature="s",
        allowed_ips=["0.0.0.0/0"], allowed_techniques=["*"],
        persistence_allowed=True, evasion_allowed=True,
        exfiltration_allowed=True, kernel_exploits_allowed=True,
    )


@pytest.fixture()
def state_on_disk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, roe):
    monkeypatch.chdir(tmp_path)
    state = EngagementState(
        engagement_id="eng_b", target_scope=["10.0.0.1"],
        operator="op", rules_of_engagement=roe,
    )
    state.phase = "exploit"
    eng = tmp_path / "engagements" / "eng_b"
    eng.mkdir(parents=True)
    (eng / "state.json").write_text(state.model_dump_json())
    return state


def _client_q(bridge: DashboardBridge) -> asyncio.Queue:
    q = bridge.register_client()
    return q


async def _drain_one_frame(q: asyncio.Queue) -> dict:
    return await asyncio.wait_for(q.get(), timeout=1.0)


@pytest.mark.asyncio
async def test_events_fan_out_with_seq(state_on_disk):
    bus = EventBus()
    bridge = DashboardBridge("eng_b", bus)
    q = _client_q(bridge)
    await bridge.start()
    await bus.emit_to_tui({"type": "phase_change", "node": "recon", "phase": "recon"})
    await bus.emit_to_tui({"type": "tool_call", "node": "recon", "tool": "nmap"})
    await asyncio.sleep(0.3)  # drain loop poll
    await bridge.stop()
    f1 = await _drain_one_frame(q)
    f2 = await _drain_one_frame(q)
    assert f1["type"] == "event" and f1["seq"] == 1
    assert f1["event"]["tool"] == "nmap"
    assert f2["seq"] == 2


@pytest.mark.asyncio
async def test_hello_replays_ring_buffer(state_on_disk):
    bus = EventBus()
    bridge = DashboardBridge("eng_b", bus, max_history=2)
    await bridge.start()
    for i in range(4):
        await bus.emit_to_tui({"type": "tick", "i": i})
    await asyncio.sleep(0.3)
    await bridge.stop()
    frames = bridge.hello_frames()
    assert frames[0]["type"] == "hello"
    events = [f for f in frames if f["type"] == "event"]
    assert len(events) == 2  # max_history=2
    assert [f["event"]["i"] for f in events] == [2, 3]  # newest kept


@pytest.mark.asyncio
async def test_secret_values_scrubbed_from_event_frames(state_on_disk):
    bus = EventBus()
    bridge = DashboardBridge("eng_b", bus)
    q = _client_q(bridge)
    bridge._known_secrets = ["SuperSecret99"]
    await bridge.start()
    await bus.emit_to_tui(
        {"type": "tool_call", "output": "hash ntlm: SuperSecret99 done"}
    )
    await asyncio.sleep(0.3)
    await bridge.stop()
    frame = await _drain_one_frame(q)
    assert "SuperSecret99" not in json.dumps(frame)
    assert "[REDACTED]" in frame["event"]["output"]


@pytest.mark.asyncio
async def test_state_frames_carry_pending_gates(state_on_disk):
    bus = EventBus()
    bridge = DashboardBridge("eng_b", bus)
    q = _client_q(bridge)
    bridge._pending_gates["7"] = {
        "gate_id": "7", "gate_type": "exploit", "target": "10.0.0.1",
        "command": "msfconsole -x ...", "risks": ["r1"],
    }
    await bridge.start()
    await bus.emit_to_tui({"type": "phase_change", "node": "exploit", "phase": "exploit"})
    await asyncio.sleep(0.3)
    await bridge.stop()
    frames = []
    while not q.empty():
        frames.append(q.get_nowait())
    state_frames = [f for f in frames if f["type"] == "state"]
    assert state_frames, "phase_change must trigger a state frame"
    assert state_frames[0]["state_summary"]["pending_hitl_gates"][0]["gate_id"] == "7"


@pytest.mark.asyncio
async def test_resolve_gate_emits_orchestrator_response(state_on_disk):
    bus = EventBus()
    bridge = DashboardBridge("eng_b", bus)
    bridge._pending_gates["9"] = {
        "gate_id": "9", "gate_type": "exploit", "target": "10.0.0.1",
        "command": "cmd", "risks": [],
    }
    await bridge.resolve_gate("9", approved=True, note=None)
    response = await asyncio.wait_for(bus.wait_for_tui_response(), timeout=1.0)
    assert response == {"response": "approve"}
    await bridge.start()
    await asyncio.sleep(0.05)
    await bridge.stop()
    with pytest.raises(ValueError):
        await bridge.resolve_gate("9", approved=False, note="double")


@pytest.mark.asyncio
async def test_resolve_unknown_gate_raises(state_on_disk):
    bridge = DashboardBridge("eng_b", EventBus())
    with pytest.raises(KeyError):
        await bridge.resolve_gate("ghost", approved=True, note=None)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/dashboard/test_bridge.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'autored.dashboard.bridge'`.

- [ ] **Step 3: Implement the bridge**

```python
# autored/dashboard/bridge.py
"""EventBus → WebSocket bridge (spec §3-§4, §6, §8).

Drains ``orchestrator_to_tui`` exactly as the TUI does (alternative
frontend, never simultaneous — CLI enforces), fans JSON frames out to
registered client queues, keeps a 500-event ring buffer for late
joiners, tracks pending HitL gates, and scrubs known secret values
from event frames. Gate resolution emits the orchestrator contract
shape ``{"response": "approve"|"reject"}`` on ``tui_to_orchestrator``.
"""
from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import Any

from autored.logging import get_logger

log = get_logger("dashboard.bridge")

POLL_INTERVAL = 0.1


def _scrub(value: Any, secrets: list[str]) -> Any:
    """Replace any known secret value inside strings with [REDACTED]."""
    if isinstance(value, str) and secrets:
        for s in secrets:
            if s and s in value:
                value = value.replace(s, "[REDACTED]")
        return value
    if isinstance(value, dict):
        return {k: _scrub(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v, secrets) for v in value]
    return value


class DashboardBridge:
    """Per-engagement event tap. One bridge per live engagement."""

    def __init__(self, engagement_id: str, bus, max_history: int = 500):
        self.engagement_id = engagement_id
        self.bus = bus
        self.seq = 0
        self.max_history = max_history
        self._history: deque[dict] = deque(maxlen=max_history)
        self._clients: set[asyncio.Queue] = set()
        self._pending_gates: dict[str, dict] = {}
        self._resolved_gates: dict[str, dict] = {}
        self._known_secrets: list[str] = []
        self._last_summary: dict = {}
        self._task: asyncio.Task | None = None
        self._stopping = asyncio.Event()

    # -- client plumbing ------------------------------------------------
    def register_client(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._clients.add(q)
        return q

    def unregister_client(self, q: asyncio.Queue) -> None:
        self._clients.discard(q)

    def hello_frames(self) -> list[dict]:
        return [
            {"type": "hello", "engagement_id": self.engagement_id,
             "seq": self.seq, "state_summary": self._last_summary},
            *self._history,
        ]

    def _fan_out(self, frame: dict) -> None:
        self._history.append(frame)
        for q in list(self._clients):
            q.put_nowait(frame)

    # -- lifecycle -------------------------------------------------------
    async def start(self) -> None:
        self._stopping.clear()
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._stopping.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._task = None

    async def _run(self) -> None:
        last_state_push = 0.0
        last_ping = 0.0
        while not self._stopping.is_set():
            event = self.bus.try_get_tui_event()
            if event is not None:
                await self._handle_event(event)
                continue  # drain eagerly
            now = time.monotonic()
            if now - last_ping >= 15.0:
                self._fan_out({"type": "ping", "ts": time.time()})
                last_ping = now
            if now - last_state_push >= 5.0:
                await self.broadcast_state()
                last_state_push = now
            await asyncio.sleep(POLL_INTERVAL)

    async def _handle_event(self, event: dict) -> None:
        self.seq += 1
        if event.get("type") == "hitl_gate":
            gate_id = str(self.seq)
            gate = {
                "gate_id": gate_id,
                "gate_type": event.get("gate_type", "unknown"),
                "target": event.get("target", ""),
                "command": event.get("command", ""),
                "risks": list(event.get("risks", [])),
                "raw": event,
            }
            self._pending_gates[gate_id] = gate
            event = {**event, "gate_id": gate_id}
        scrubbed = _scrub(event, self._known_secrets)
        self._fan_out({"type": "event", "seq": self.seq, "event": scrubbed})
        if event.get("type") == "phase_change":
            await self.broadcast_state()

    # -- state snapshots --------------------------------------------------
    async def broadcast_state(self) -> None:
        from autored.dashboard.api import state_summary
        from autored.persistence.filesystem import load_state_from_disk

        try:
            state = load_state_from_disk(self.engagement_id)
        except Exception as e:  # noqa: BLE001 — snapshot is best-effort
            log.warning("dashboard_state_load_failed", error=str(e))
            state = None
        if state is None:
            return
        self._known_secrets = [
            s.secret_value for s in getattr(state, "harvested_secrets", [])
            if getattr(s, "secret_value", "")
        ]
        summary = state_summary(state, ws_mode=True)
        summary["pending_hitl_gates"] = self.pending_gate_summaries()
        self._last_summary = summary
        self.seq += 1
        frame = {"type": "state", "seq": self.seq, "state_summary": summary}
        self._history.append(frame)
        for q in list(self._clients):
            q.put_nowait(frame)

    def pending_gate_summaries(self) -> list[dict]:
        return [
            {k: g[k] for k in ("gate_id", "gate_type", "target", "command", "risks")}
            for g in self._pending_gates.values()
        ]

    # -- HitL resolution ---------------------------------------------------
    async def resolve_gate(self, gate_id: str, approved: bool, note: str | None) -> dict:
        if gate_id not in self._pending_gates:
            if gate_id in self._resolved_gates:
                raise ValueError(
                    f"gate {gate_id} already resolved: "
                    f"{self._resolved_gates[gate_id]['decision']}"
                )
            raise KeyError(f"unknown gate {gate_id}")
        self._resolved_gates[gate_id] = {
            "decision": "approve" if approved else "reject", "note": note,
        }
        del self._pending_gates[gate_id]
        await self.bus.emit_to_orchestrator(
            {"response": "approve" if approved else "reject"}
        )
        return {"status": "resolved",
                "decision": self._resolved_gates[gate_id]["decision"]}
```

In `autored/dashboard/__init__.py` extend:

```python
from autored.dashboard.api import create_app, state_summary
from autored.dashboard.bridge import DashboardBridge

__all__ = ["create_app", "state_summary", "DashboardBridge"]
```

Note: ping frames land in client queues only after 15 s, so the test sleeps (0.3 s) never see them — no test changes needed.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/dashboard/test_bridge.py -v`
Expected: PASS (6 passed). Then `uv run pytest -q` → full suite green.

- [ ] **Step 5: Commit**

```bash
git add autored/dashboard/bridge.py autored/dashboard/__init__.py tests/unit/dashboard/test_bridge.py
git commit -m "feat: dashboard bridge with ring buffer, fan-out, and gate registry"
```

---

### Task 5: WS Endpoint + HitL POST Endpoint

**Files:**
- Create: `autored/dashboard/ws.py`
- Modify: `autored/dashboard/api.py` (`create_app(bridges: dict[str, DashboardBridge] | None = None)`)
- Test: `tests/unit/dashboard/test_hitl_ws.py` (NEW)

**Interfaces:**
- Consumes: `DashboardBridge` (Task 4 exact names), `create_app` (Task 2).
- Produces: `create_app(bridges=...)` — a registry `{engagement_id: bridge}`; routes `WS /ws/{engagement_id}` and `POST /api/engagements/{id}/hitl/{gate_id}` (200 resolved / 409 already-resolved / 404 no live bridge).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/dashboard/test_hitl_ws.py
"""WS endpoint + HitL POST: full resolve loop against a real EventBus."""
import asyncio

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.testclient import TestClient

from autored.dashboard import create_app
from autored.dashboard.bridge import DashboardBridge
from autored.tui.event_bus import EventBus


@pytest.fixture()
def bridges():
    bus = EventBus()
    bridge = DashboardBridge("eng_ws", bus)
    return {"eng_ws": bridge}, bridge, bus


def test_ws_hello_frame_on_connect(bridges):
    """Smoke: a connected client receives the hello frame (drain-loop
    frame assertions live in test_bridge.py where the loop is controlled)."""
    registry, bridge, bus = bridges
    app = create_app(bridges=registry)
    with TestClient(app) as client:
        with client.websocket_connect("/ws/eng_ws") as ws:
            hello = ws.receive_json()
            assert hello["type"] == "hello"
            assert hello["engagement_id"] == "eng_ws"


def test_ws_unknown_engagement_closes_4404(bridges):
    registry, bridge, bus = bridges
    app = create_app(bridges=registry)
    with TestClient(app) as client:
        with pytest.raises(Exception):  # noqa: B017 — close before hello
            with client.websocket_connect("/ws/ghost"):
                pass


@pytest.mark.asyncio
async def test_hitl_post_resolves_pending_gate(bridges):
    registry, bridge, bus = bridges
    app = create_app(bridges=registry)
    bridge._pending_gates["3"] = {
        "gate_id": "3", "gate_type": "exploit", "target": "10.0.0.1",
        "command": "cmd", "risks": [],
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/api/engagements/eng_ws/hitl/3", json={"approved": True}
        )
        assert resp.status_code == 200
        assert resp.json()["decision"] == "approve"
        # the orchestrator contract: wait_for_tui_response returns the dict
        response = await asyncio.wait_for(bus.wait_for_tui_response(), timeout=1.0)
        assert response == {"response": "approve"}


@pytest.mark.asyncio
async def test_hitl_post_double_resolve_409(bridges):
    registry, bridge, bus = bridges
    app = create_app(bridges=registry)
    bridge._pending_gates["4"] = {
        "gate_id": "4", "gate_type": "exploit", "target": "t",
        "command": "c", "risks": [],
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        await client.post("/api/engagements/eng_ws/hitl/4", json={"approved": False})
        resp = await client.post("/api/engagements/eng_ws/hitl/4", json={"approved": True})
        assert resp.status_code == 409
        assert "reject" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_hitl_post_no_live_bridge_404(bridges):
    app = create_app(bridges={})
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/api/engagements/eng_ws/hitl/1", json={"approved": True})
        assert resp.status_code == 404
```

Note: unknown-gate POSTs return `409` (not 404) per spec §5 — the gate may exist in history as resolved. Only a missing live bridge is `404`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/dashboard/test_hitl_ws.py -v`
Expected: FAIL — `create_app` doesn't accept `bridges`, routes 404.

- [ ] **Step 3: Implement WS + HitL routes and the lifespan**

```python
# autored/dashboard/ws.py
"""WebSocket fan-out endpoint (spec §4, §8).

The HitL POST lives in ``api.py`` (Task 5) where the per-app bridge
registry closure exists — this module only owns the WS endpoint.
"""
from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from autored.logging import get_logger

log = get_logger("dashboard.ws")

router = APIRouter()


@router.websocket("/ws/{engagement_id}")
async def ws_endpoint(websocket: WebSocket, engagement_id: str) -> None:
    bridges = websocket.app.state.bridges
    bridge = bridges.get(engagement_id)
    if bridge is None:
        await websocket.close(code=4404)
        return
    await websocket.accept()
    q = bridge.register_client()
    try:
        for frame in bridge.hello_frames():
            await websocket.send_json(frame)
        while True:
            client_msg = await websocket.receive_json()
            # Only pings are defined client→server (spec §4) — receive and
            # ignore; reconnect handles staleness.
            _ = client_msg
    except WebSocketDisconnect:
        pass
    finally:
        bridge.unregister_client(q)
```

In `autored/dashboard/api.py`, change the factory signature and add the POST route plus the router include:

```python
def create_app(bridges: dict[str, "DashboardBridge"] | None = None) -> FastAPI:
    bridges = bridges if bridges is not None else {}
    app = FastAPI(title="AutoRed Dashboard", docs_url=None, redoc_url=None)
    app.state.bridges = bridges

    from autored.dashboard.ws import router as ws_router

    app.include_router(ws_router)

    @app.post("/api/engagements/{engagement_id}/hitl/{gate_id}")
    async def resolve_hitl(engagement_id: str, gate_id: str, body: dict):
        bridge = bridges.get(engagement_id)
        if bridge is None:
            raise HTTPException(
                status_code=404, detail="no live dashboard bridge for this engagement"
            )
        try:
            return await bridge.resolve_gate(
                gate_id, bool(body.get("approved", False)), body.get("note")
            )
        except ValueError as e:
            raise HTTPException(status_code=409, detail=str(e))
        except KeyError as e:
            raise HTTPException(status_code=409, detail=str(e)) from e

    # ... existing routes from Task 2/3 unchanged, and create_app still ends with `return app` ...
```

(The `"DashboardBridge"` forward reference in the type hint needs no import — it is quoted. Task 2's `create_app()` calls with no argument keep working because `bridges=None` defaults to an empty registry.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/dashboard/test_hitl_ws.py -v`
Expected: PASS (4 passed). Then `uv run pytest -q` → green.

- [ ] **Step 5: Commit**

```bash
git add autored/dashboard/ws.py autored/dashboard/api.py tests/unit/dashboard/test_hitl_ws.py
git commit -m "feat: dashboard websocket stream and hitl resolution endpoint"
```

---

### Task 6: CLI `--dashboard` Wiring + Supervised Server Task

**Files:**
- Modify: `autored/cli.py` (headless `_run()` — bus construction moves up, bridge + uvicorn task started)
- Modify: `autored/dashboard/server.py` (NEW — uvicorn config + supervised runner)
- Test: `tests/unit/dashboard/test_cli_dashboard.py` (append)

**Interfaces:**
- Consumes: `DashboardBridge`, `create_app(bridges=...)`.
- Produces: `autored/dashboard/server.py: start_dashboard_server(bridge, port) -> uvicorn.Server` and `await shutdown_dashboard(server)`. CLI pattern: bus constructed before `_run()`, `config["configurable"]["event_bus"] = bus`, bridge drains it during the graph run.

- [ ] **Step 1: Write the failing tests (append)**

```python
import asyncio

import pytest


@pytest.mark.asyncio
async def test_supervised_server_survives_crash():
    """A raising dashboard server must not propagate into the run."""
    from autored.dashboard.server import run_dashboard_supervised

    async def exploding():
        raise RuntimeError("uvicorn exploded")

    task = asyncio.create_task(exploding())
    await run_dashboard_supervised(task)  # must not raise
    assert task.done()


@pytest.mark.asyncio
async def test_supervised_server_clean_shutdown():
    from autored.dashboard.server import run_dashboard_supervised

    started = asyncio.Event()

    async def quick_server():
        started.set()
        await asyncio.sleep(10)

    task = asyncio.create_task(quick_server())
    await asyncio.wait_for(started.wait(), timeout=1.0)
    await run_dashboard_supervised(task, shutdown=True)
    assert task.cancelled() or task.done()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/dashboard/test_cli_dashboard.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'autored.dashboard.server'`.

- [ ] **Step 3: Implement server.py and the CLI wiring**

```python
# autored/dashboard/server.py
"""Uvicorn hosting + crash-isolation supervisor (spec §2, §8)."""
from __future__ import annotations

import asyncio

import uvicorn

from autored.logging import get_logger

log = get_logger("dashboard.server")


def build_server(app, port: int) -> uvicorn.Server:
    config = uvicorn.Config(
        app, host="127.0.0.1", port=port, log_level="warning", lifespan="off",
    )
    return uvicorn.Server(config)


async def run_dashboard_supervised(task: asyncio.Task, shutdown: bool = False) -> None:
    """Await a dashboard server task; a crash is logged, never propagated."""
    try:
        await task
    except asyncio.CancelledError:
        raise
    except Exception as e:  # noqa: BLE001 — server isolation (spec §8)
        log.error("dashboard_server_crashed_run_continues", error=str(e))
    finally:
        if shutdown and not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
```

(`lifespan="off"` — the bridge is started explicitly by the CLI, so uvicorn's lifespan adds nothing and `TestClient`-free in-process serving stays simple.)

In `autored/cli.py`, two edits to the headless path.

**Edit 1 — hoist the EventBus out of `_run()`** (it must exist before the branch so the bridge can share it). Current code inside `_run()`:

```python
            from autored.tui.event_bus import EventBus

            bus = EventBus()
            config = {
```

becomes — bus constructed once before `_run()` is defined, `_run()` closes over it:

```python
    from autored.tui.event_bus import EventBus

    bus = EventBus()

    async def _run() -> object:
        checkpointer = await make_checkpointer(engagement_id)
        try:
            graph = build_phase6_graph(checkpointer)
            config = {
                "configurable": {
                    "thread_id": engagement_id,
                    "event_bus": bus,
                }
            }
            return await graph.ainvoke(state, config=config)
        finally:
            # ... existing checkpointer-close finally body unchanged ...
```

**Edit 2 — replace the trailing `asyncio.run(_run())` invocation** (wherever it currently sits at the end of `run()`) with the dashboard branch. `run()` is sync (Typer), so every await lives inside one wrapper coroutine:

```python
    if dashboard:
        async def _dashboard_run() -> object:
            from autored.dashboard import DashboardBridge, create_app
            from autored.dashboard.server import (
                build_server,
                run_dashboard_supervised,
            )

            bridge = DashboardBridge(engagement_id, bus)
            server = build_server(
                create_app(bridges={engagement_id: bridge}), dashboard_port,
            )
            server_task = asyncio.create_task(server.serve())
            console.print(
                f"[bold green]Dashboard:[/] http://127.0.0.1:{dashboard_port}"
            )
            await bridge.start()  # drain loop must run while the graph runs
            try:
                return await _run()
            finally:
                server.should_exit = True
                try:
                    await asyncio.wait_for(server_task, timeout=5)
                except Exception as e:  # noqa: BLE001 — isolation (spec §8)
                    log.warning("dashboard_shutdown_error", error=str(e))
                await run_dashboard_supervised(server_task)
                await bridge.stop()

        result = asyncio.run(_dashboard_run())
    else:
        result = asyncio.run(_run())
```

(`import asyncio` must already be present at the top of `cli.py` — it is, for `asyncio.iscoroutine` in the checkpointer helper. If `result` was previously unused after `asyncio.run(_run())`, keep whatever reporting the existing code does with it unchanged.)

- [ ] **Step 4: Run tests + full suite**

Run: `uv run pytest tests/unit/dashboard/ -v && uv run pytest -q`
Expected: all dashboard tests pass, full suite green.

- [ ] **Step 5: Commit**

```bash
git add autored/cli.py autored/dashboard/server.py tests/unit/dashboard/test_cli_dashboard.py
git commit -m "feat: run engagements with live dashboard server via --dashboard"
```

---

### Task 7: Frontend Scaffold + EngagementList View

**Files:**
- Create: `frontend/package.json`, `frontend/vite.config.ts`, `frontend/tsconfig.json`, `frontend/index.html`, `frontend/src/main.tsx`, `frontend/src/App.tsx`, `frontend/src/api.ts`, `frontend/src/types.ts`, `frontend/src/views/EngagementList.tsx`, `frontend/src/views/EngagementList.module.css`, `frontend/src/styles/global.css`
- Test: `frontend/src/views/EngagementList.test.tsx` + `frontend/vitest.config.ts`

**Interfaces:**
- Consumes: `GET /api/engagements` → `[{engagement_id, target, phase, started_at, operator}]`.
- Produces: `api.ts: listEngagements(), fetchState(id), resolveHitl(id, gateId, approved)`, `types.ts: EngagementRow, StateSummary, HitlGate`. Routes `/` → EngagementList, `/engagements/:id` → EngagementDetail (Task 8).

- [ ] **Step 1: Scaffold the project files**

```json
// frontend/package.json
{
  "name": "autored-dashboard",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc -b && vite build",
    "test": "vitest run",
    "preview": "vite preview"
  },
  "dependencies": {
    "@xyflow/react": "^12.3.0",
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "react-router": "^6.28.0"
  },
  "devDependencies": {
    "@testing-library/jest-dom": "^6.6.0",
    "@testing-library/react": "^16.1.0",
    "@types/react": "^18.3.12",
    "@types/react-dom": "^18.3.1",
    "@vitejs/plugin-react": "^4.3.3",
    "jsdom": "^25.0.1",
    "typescript": "^5.6.3",
    "vite": "^5.4.10",
    "vitest": "^2.1.8"
  }
}
```

```ts
// frontend/vite.config.ts
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8500",
      "/ws": { target: "ws://127.0.0.1:8500", ws: true },
    },
  },
});
```

```ts
// frontend/vitest.config.ts
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test-setup.ts"],
  },
});
```

```ts
// frontend/src/test-setup.ts
import "@testing-library/jest-dom/vitest";
```

```html
<!-- frontend/index.html -->
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>AutoRed Dashboard</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

```tsx
// frontend/src/main.tsx
import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Route, Routes } from "react-router";
import EngagementDetail from "./views/EngagementDetail";
import EngagementList from "./views/EngagementList";
import "./styles/global.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<EngagementList />} />
        <Route path="/engagements/:id" element={<EngagementDetail />} />
      </Routes>
    </BrowserRouter>
  </React.StrictMode>,
);
```

```ts
// frontend/src/types.ts
export interface EngagementRow {
  engagement_id: string;
  target: string;
  phase: string;
  started_at: string;
  operator: string;
}

export interface HitlGate {
  gate_id: string;
  gate_type: string;
  target: string;
  command: string;
  risks: string[];
}

export interface StateSummary {
  phase: string;
  engagement_id: string;
  target_scope: string[];
  hosts: HostRow[];
  services: ServiceRow[];
  findings: FindingRow[];
  footholds: FootholdRow[];
  harvested_secrets: SecretRow[];
  pivots: unknown[];
  movement_paths: MovementPath[];
  sub_engagements: unknown[];
  cleanup_results: unknown[];
  attack_hypotheses: unknown;
  pending_hitl_gates: HitlGate[];
}

export interface HostRow { ip: string; hostname: string | null; os: string | null; }
export interface ServiceRow { host_ip: string; port: number; protocol: string; service: string; }
export interface FindingRow { title: string; severity: string; host: string; }
export interface FootholdRow { host_ip: string; method: string; access_type: string; }
export interface SecretRow { secret_type: string; source: string; secret_value: string; }
export interface MovementPath { from_host: string; to_host: string; method: string; credential_used: string; }
```

```ts
// frontend/src/api.ts
import type { EngagementRow, StateSummary } from "./types";

async function getJson<T>(path: string): Promise<T> {
  const resp = await fetch(path);
  if (!resp.ok) throw new Error(`${resp.status} ${path}`);
  return resp.json();
}

export function listEngagements(): Promise<EngagementRow[]> {
  return getJson("/api/engagements");
}

export function fetchState(id: string): Promise<StateSummary> {
  return getJson(`/api/engagements/${id}/state`);
}

export function fetchRoe(id: string): Promise<Record<string, unknown>> {
  return getJson(`/api/engagements/${id}/roe`);
}

export async function resolveHitl(
  id: string, gateId: string, approved: boolean,
): Promise<void> {
  const resp = await fetch(
    `/api/engagements/${id}/hitl/${gateId}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ approved }),
    },
  );
  if (resp.status === 409) throw new Error("already-resolved");
  if (!resp.ok) throw new Error(`${resp.status}`);
}
```

```tsx
// frontend/src/views/EngagementList.tsx
import { useEffect, useState } from "react";
import { Link } from "react-router";
import { listEngagements } from "../api";
import type { EngagementRow } from "../types";
import styles from "./EngagementList.module.css";

export default function EngagementList() {
  const [rows, setRows] = useState<EngagementRow[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const tick = () =>
      listEngagements()
        .then((r) => alive && (setRows(r), setError(null)))
        .catch((e) => alive && setError(String(e)));
    tick();
    const h = setInterval(tick, 10_000); // spec §7.1: 10 s poll, no WS here
    return () => { alive = false; clearInterval(h); };
  }, []);

  return (
    <div className={styles.page}>
      <h1>AutoRed Engagements</h1>
      {error && <p className={styles.error}>{error}</p>}
      <table className={styles.table}>
        <thead>
          <tr>
            <th>ID</th><th>Target</th><th>Phase</th><th>Started</th><th>Operator</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.engagement_id}>
              <td>
                {r.phase === "running" || !isTerminal(r.phase) ? (
                  <Link to={`/engagements/${r.engagement_id}`}>{r.engagement_id}</Link>
                ) : (
                  r.engagement_id
                )}
              </td>
              <td>{r.target}</td>
              <td><span className={styles[`phase_${r.phase}`] ?? styles.badge}>{r.phase}</span></td>
              <td>{r.started_at}</td>
              <td>{r.operator}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function isTerminal(phase: string): boolean {
  return phase === "done" || phase === "failed" || phase === "aborted";
}
```

```css
/* frontend/src/views/EngagementList.module.css */
.page { margin: 2rem auto; max-width: 60rem; font-family: system-ui, sans-serif; color: #d4d4d8; }
.table { width: 100%; border-collapse: collapse; }
.table th, .table td { padding: 0.5rem 0.75rem; text-align: left; border-bottom: 1px solid #3f3f46; }
.table th { color: #a1a1aa; font-weight: 600; }
.badge { padding: 0.1rem 0.5rem; border-radius: 9999px; background: #3f3f46; }
.phase_done { composes badge; background: #166534; }
.phase_failed { composes badge; background: #991b1b; }
.error { color: #f87171; }
a { color: #60a5fa; }
```

```css
/* frontend/src/styles/global.css */
body { background: #18181b; margin: 0; }
```

- [ ] **Step 2: Write the failing test, install deps, run**

```tsx
// frontend/src/views/EngagementList.test.tsx
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import EngagementList from "./EngagementList";

const listEngagements = vi.fn();

vi.mock("../api", () => ({
  listEngagements: (...args: unknown[]) => listEngagements(...args),
}));

describe("EngagementList", () => {
  beforeEach(() => listEngagements.mockReset());

  it("renders rows and links running engagements", async () => {
    listEngagements.mockResolvedValue([
      { engagement_id: "eng_1", target: "10.0.0.1", phase: "exploit",
        started_at: "2026-09-27", operator: "op" },
    ]);
    render(
      <MemoryRouter>
        <EngagementList />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("eng_1")).toBeTruthy());
    const link = screen.getByRole("link", { name: "eng_1" });
    expect(link.getAttribute("href")).toBe("/engagements/eng_1");
  });

  it("shows an error card on API failure", async () => {
    listEngagements.mockRejectedValue(new Error("500"));
    render(
      <MemoryRouter>
        <EngagementList />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText(/500/)).toBeTruthy());
  });
});
```

Run: `npm --prefix frontend install && npm --prefix frontend run test`
Expected: FAIL first if `EngagementDetail` is imported by `main.tsx` but missing — so also create a stub `frontend/src/views/EngagementDetail.tsx` exporting `export default function EngagementDetail() { return <p>detail — Task 8</p>; }` (replaced in Task 8). Then tests PASS (2 passed).

- [ ] **Step 3: Commit**

```bash
git add frontend/ .gitignore
git commit -m "feat: dashboard frontend scaffold with engagement list view"
```

(Ensure `.gitignore` has `frontend/node_modules/` and `frontend/dist/` — add if missing.)

---

### Task 8: EngagementDetail — Socket Hook, Timeline, Activity Log, Panels

**Files:**
- Create: `frontend/src/socket.ts`, `frontend/src/views/EngagementDetail.tsx`, `frontend/src/components/PhaseTimeline.tsx`, `frontend/src/components/ActivityLog.tsx`, `frontend/src/components/DataPanels.tsx`, `frontend/src/components/StateInspector.tsx`, `frontend/src/components/RoeCard.tsx`, plus one `.module.css` each (lean)
- Modify: replace the Task 7 `EngagementDetail.tsx` stub

**Interfaces:**
- Consumes: `WS /ws/{id}` frames (`hello`/`event`/`state`), `fetchState`, `fetchRoe`, types from Task 7.
- Produces: `socket.ts: useEngagementSocket(id) -> { summary: StateSummary | null, events: EventFrame[], connected: boolean }` with reconnect+resync (spec §7.2, §8). Task 9 consumes `summary.pending_hitl_gates` and `events` for the modal.

- [ ] **Step 1: Implement the socket hook**

```ts
// frontend/src/socket.ts
import { useEffect, useReducer, useRef } from "react";
import { fetchState } from "./api";
import type { StateSummary } from "./types";

export interface EventFrame {
  seq: number;
  event: Record<string, unknown> & { type: string; node?: string };
}

interface SocketState {
  summary: StateSummary | null;
  events: EventFrame[];
  connected: boolean;
}

type Action =
  | { kind: "hello"; summary: StateSummary }
  | { kind: "event"; frame: EventFrame }
  | { kind: "state"; summary: StateSummary }
  | { kind: "connected"; connected: boolean };

function reducer(state: SocketState, action: Action): SocketState {
  switch (action.kind) {
    case "hello":
      return { ...state, summary: action.summary, connected: true };
    case "event":
      return { ...state, events: [action.frame, ...state.events].slice(0, 500) };
    case "state":
      return { ...state, summary: action.summary };
    case "connected":
      return { ...state, connected: action.connected };
  }
}

const PHASES = ["recon", "vuln", "exploit", "postex", "lateral", "cleanup", "report", "done"];

export function useEngagementSocket(id: string) {
  const [state, dispatch] = useReducer(reducer, {
    summary: null, events: [], connected: false,
  });
  const backoff = useRef(1000);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let closed = false;

    async function resync() {
      try {
        const summary = await fetchState(id);
        dispatch({ kind: "state", summary });
      } catch { /* 404 before run starts — WS retry covers it */ }
    }

    function connect() {
      if (closed) return;
      const proto = location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${proto}://${location.host}/ws/${id}`);
      ws.onopen = () => { backoff.current = 1000; dispatch({ kind: "connected", connected: true }); };
      ws.onmessage = (msg) => {
        const frame = JSON.parse(msg.data);
        if (frame.type === "hello") dispatch({ kind: "hello", summary: frame.state_summary });
        else if (frame.type === "state") dispatch({ kind: "state", summary: frame.state_summary });
        else if (frame.type === "event") {
          dispatch({ kind: "event", frame });
          if (frame.event?.type === "phase_change") void resync();
        }
      };
      ws.onclose = () => {
        dispatch({ kind: "connected", connected: false });
        if (closed) return;
        void resync(); // spec §8: reconnect re-syncs from GET /state
        setTimeout(connect, backoff.current);
        backoff.current = Math.min(backoff.current * 2, 30_000);
      };
    }

    void resync();
    connect();
    return () => { closed = true; ws?.close(); };
  }, [id]);

  return state;
}

export { PHASES };
```

- [ ] **Step 2: Implement the view and components**

```tsx
// frontend/src/views/EngagementDetail.tsx
// (HitLModal is added to this file in Task 9 — it does not exist yet here.)
import { useEffect, useState } from "react";
import { useParams } from "react-router";
import ActivityLog from "../components/ActivityLog";
import DataPanels from "../components/DataPanels";
import PhaseTimeline from "../components/PhaseTimeline";
import RoeCard from "../components/RoeCard";
import StateInspector from "../components/StateInspector";
import { fetchRoe } from "../api";
import { useEngagementSocket } from "../socket";
import styles from "./EngagementDetail.module.css";

export default function EngagementDetail() {
  const { id = "" } = useParams();
  const { summary, events, connected } = useEngagementSocket(id);
  const [roe, setRoe] = useState<Record<string, unknown> | null>(null);

  useEffect(() => {
    fetchRoe(id).then(setRoe).catch(() => setRoe(null));
  }, [id]);

  if (!summary) {
    return <p className={styles.loading}>Loading engagement {id}… (or not found)</p>;
  }

  return (
    <div className={styles.page}>
      <PhaseTimeline phase={summary.phase} />
      <p className={styles.conn}>
        {connected ? "live" : "reconnecting…"} · target {summary.target_scope.join(", ")}
      </p>
      <div className={styles.columns}>
        <ActivityLog events={events} />
        <DataPanels summary={summary} />
      </div>
      <StateInspector summary={summary} />
      {roe && <RoeCard roe={roe} />}
    </div>
  );
}
```

```tsx
// frontend/src/components/PhaseTimeline.tsx
import { PHASES } from "../socket";
import styles from "./PhaseTimeline.module.css";

export default function PhaseTimeline({ phase }: { phase: string }) {
  const activeIdx = PHASES.indexOf(phase);
  return (
    <div className={styles.bar}>
      {PHASES.map((p, i) => (
        <span
          key={p}
          className={[
            styles.step,
            i < activeIdx ? styles.done : "",
            i === activeIdx ? styles.active : "",
          ].join(" ")}
        >
          {i < activeIdx ? "✓ " : ""}{p}
        </span>
      ))}
    </div>
  );
}
```

```tsx
// frontend/src/components/ActivityLog.tsx
import type { EventFrame } from "../socket";
import styles from "./ActivityLog.module.css";

export default function ActivityLog({ events }: { events: EventFrame[] }) {
  return (
    <div className={styles.log}>
      <h3>Activity</h3>
      {events.length === 0 && <p className={styles.dim}>waiting for events…</p>}
      {events.map((f) => (
        <div key={`${f.seq}`} className={styles.line}>
          <span className={styles.seq}>#{f.seq}</span>
          <span className={styles.type}>{String(f.event.type)}</span>
          <span>{describe(f.event)}</span>
        </div>
      ))}
    </div>
  );
}

function describe(e: Record<string, unknown> & { type: string }): string {
  if (e.type === "hitl_gate") return `gate ${(e.gate_id as string) ?? ""} — ${String(e.command ?? "")}`;
  if (e.type === "phase_change") return `→ ${String(e.phase ?? e.node ?? "")}`;
  if (typeof e.tool === "string") return e.tool;
  if (typeof e.message === "string") return e.message;
  return JSON.stringify(e).slice(0, 120);
}
```

```tsx
// frontend/src/components/DataPanels.tsx
import { useState } from "react";
import type { StateSummary } from "../types";
import styles from "./DataPanels.module.css";

const TABS = ["Findings", "Secrets", "Hosts & Footholds"] as const;

export default function DataPanels({ summary }: { summary: StateSummary }) {
  const [tab, setTab] = useState<(typeof TABS)[number]>("Findings");
  const capped = (v: unknown) =>
    v && typeof v === "object" && "count" in (v as Record<string, unknown>)
      ? `${(v as { count: number }).count} items (full list via state inspector)`
      : null;

  return (
    <div className={styles.panels}>
      <div className={styles.tabs}>
        {TABS.map((t) => (
          <button key={t} className={tab === t ? styles.on : ""} onClick={() => setTab(t)}>
            {t}
          </button>
        ))}
      </div>
      {tab === "Findings" && (
        <table className={styles.table}>
          <thead><tr><th>Title</th><th>Severity</th><th>Host</th></tr></thead>
          <tbody>
            {summary.findings.map((f, i) => (
              <tr key={i}><td>{f.title}</td><td>{f.severity}</td><td>{f.host}</td></tr>
            ))}
          </tbody>
        </table>
      )}
      {tab === "Secrets" && (
        <table className={styles.table}>
          <thead><tr><th>Type</th><th>Source</th><th>Value</th></tr></thead>
          <tbody>
            {summary.harvested_secrets.map((s, i) => (
              <tr key={i}><td>{s.secret_type}</td><td>{s.source}</td><td><code>{s.secret_value}</code></td></tr>
            ))}
          </tbody>
        </table>
      )}
      {tab === "Hosts & Footholds" && (
        <table className={styles.table}>
          <thead><tr><th>Host</th><th>Foothold</th><th>Access</th></tr></thead>
          <tbody>
            {summary.footholds.map((f, i) => (
              <tr key={i}><td>{f.host_ip}</td><td>{f.method}</td><td>{f.access_type}</td></tr>
            ))}
          </tbody>
        </table>
      )}
      {capped(summary.findings) && <p className={styles.dim}>{capped(summary.findings)}</p>}
    </div>
  );
}
```

```tsx
// frontend/src/components/StateInspector.tsx
import { useState } from "react";
import type { StateSummary } from "../types";
import styles from "./StateInspector.module.css";

export default function StateInspector({ summary }: { summary: StateSummary }) {
  const [open, setOpen] = useState(false);
  return (
    <details className={styles.inspector} open={open} onToggle={(e) => setOpen((e.target as HTMLDetailsElement).open)}>
      <summary>State inspector</summary>
      <pre>{JSON.stringify(summary, null, 2)}</pre>
    </details>
  );
}
```

```tsx
// frontend/src/components/RoeCard.tsx
import styles from "./RoeCard.module.css";

export default function RoeCard({ roe }: { roe: Record<string, unknown> }) {
  return (
    <div className={styles.card}>
      <h3>Rules of Engagement (read-only)</h3>
      <ul>
        <li>name: {String(roe.engagement_name)}</li>
        <li>operator: {String(roe.operator)}</li>
        <li>allowed_ips: {JSON.stringify(roe.allowed_ips)}</li>
        <li>allowed_techniques: {JSON.stringify(roe.allowed_techniques)}</li>
        <li>hitl_mode: {String(roe.hitl_mode)}</li>
      </ul>
    </div>
  );
}
```

CSS modules — complete contents for each file imported above:

```css
/* frontend/src/views/EngagementDetail.module.css */
.page { margin: 1.5rem auto; max-width: 72rem; font-family: system-ui, sans-serif; color: #d4d4d8; padding: 0 1rem; }
.conn { color: #a1a1aa; font-size: 0.85rem; margin: 0.5rem 0 1rem; }
.conn.live { color: #4ade80; }
.columns { display: grid; grid-template-columns: 1fr 2fr; gap: 1rem; align-items: start; }
.loading { color: #a1a1aa; padding: 2rem; font-family: system-ui, sans-serif; }
@media (max-width: 60rem) { .columns { grid-template-columns: 1fr; } }
```

```css
/* frontend/src/components/PhaseTimeline.module.css */
.bar { display: flex; gap: 0.25rem; flex-wrap: wrap; }
.step { padding: 0.25rem 0.75rem; border-radius: 9999px; background: #27272a; color: #71717a; font-size: 0.85rem; }
.done { background: #166534; color: #dcfce7; }
.active { background: #b45309; color: #fef3c7; font-weight: 700; }
```

```css
/* frontend/src/components/ActivityLog.module.css */
.log { background: #1c1c1f; border: 1px solid #3f3f46; border-radius: 8px; padding: 0.75rem; max-height: 60vh; overflow-y: auto; }
.log h3 { margin: 0 0 0.5rem; font-size: 0.9rem; color: #a1a1aa; }
.line { display: flex; gap: 0.5rem; padding: 0.2rem 0; border-bottom: 1px solid #27272a; font-size: 0.8rem; font-family: ui-monospace, monospace; }
.seq { color: #52525b; min-width: 3rem; }
.type { color: #60a5fa; min-width: 7rem; }
.dim { color: #52525b; font-size: 0.8rem; }
```

```css
/* frontend/src/components/DataPanels.module.css */
.panels { background: #1c1c1f; border: 1px solid #3f3f46; border-radius: 8px; padding: 0.75rem; }
.tabs { display: flex; gap: 0.25rem; margin-bottom: 0.75rem; }
.tabs button { background: #27272a; color: #a1a1aa; border: none; padding: 0.3rem 0.8rem; border-radius: 6px; cursor: pointer; font-size: 0.8rem; }
.tabs button.on { background: #b45309; color: #fef3c7; }
.table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
.table th, .table td { padding: 0.35rem 0.5rem; text-align: left; border-bottom: 1px solid #27272a; }
.table th { color: #a1a1aa; }
.dim { color: #52525b; font-size: 0.75rem; }
```

```css
/* frontend/src/components/StateInspector.module.css */
.inspector { background: #1c1c1f; border: 1px solid #3f3f46; border-radius: 8px; padding: 0.75rem; margin-top: 1rem; font-size: 0.8rem; }
.inspector summary { cursor: pointer; color: #a1a1aa; }
.inspector pre { max-height: 40vh; overflow: auto; color: #d4d4d8; }
```

```css
/* frontend/src/components/RoeCard.module.css */
.card { background: #1c1c1f; border: 1px solid #3f3f46; border-radius: 8px; padding: 0.75rem 1rem; margin-top: 1rem; font-size: 0.85rem; }
.card h3 { margin: 0 0 0.5rem; font-size: 0.9rem; color: #a1a1aa; }
.card ul { margin: 0; padding-left: 1.25rem; }
```

- [ ] **Step 3: Tests — timeline smoke + socket reconnect/resync (spec §9)**

```tsx
// frontend/src/components/PhaseTimeline.test.tsx
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import PhaseTimeline from "./PhaseTimeline";

describe("PhaseTimeline", () => {
  it("marks completed phases and the active one", () => {
    render(<PhaseTimeline phase="exploit" />);
    expect(screen.getByText(/✓ recon/)).toBeTruthy();
    expect(screen.getByText("exploit")).toBeTruthy();
  });
});
```

```tsx
// frontend/src/socket.test.tsx
import { renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useEngagementSocket } from "./socket";

class MockWebSocket {
  static instances: MockWebSocket[] = [];
  onopen: (() => void) | null = null;
  onmessage: ((e: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  constructor(public url: string) { MockWebSocket.instances.push(this); }
  close() { this.onclose?.(); }
  send() {}
}

const fetchState = vi.fn();
vi.mock("./api", () => ({ fetchState: (...a: unknown[]) => fetchState(...a) }));

describe("useEngagementSocket", () => {
  beforeEach(() => {
    MockWebSocket.instances = [];
    fetchState.mockReset();
    vi.stubGlobal("WebSocket", MockWebSocket as unknown as typeof WebSocket);
  });
  afterEach(() => vi.unstubAllGlobals());

  it("seeds from hello and resyncs from GET /state after a drop", async () => {
    fetchState.mockResolvedValue({ phase: "recon", pending_hitl_gates: [] });
    const { result } = renderHook(() => useEngagementSocket("eng_1"));
    const ws = MockWebSocket.instances[0];
    expect(ws.url.endsWith("/ws/eng_1")).toBe(true);
    ws.onopen?.();
    ws.onmessage?.({
      data: JSON.stringify({
        type: "hello", engagement_id: "eng_1", seq: 0,
        state_summary: { phase: "recon", pending_hitl_gates: [] },
      }),
    });
    await waitFor(() => expect(result.current.summary?.phase).toBe("recon"));
    expect(result.current.connected).toBe(true);
    // drop → immediate resync fetch (initial + resync = 2 calls)
    ws.onclose?.();
    await waitFor(() => expect(fetchState).toHaveBeenCalledTimes(2));
    expect(result.current.connected).toBe(false);
  });
});
```

Run: `npm --prefix frontend run test`
Expected: PASS (4 tests total incl. Task 7's 2).

- [ ] **Step 4: Commit**

```bash
git add frontend/src
git commit -m "feat: engagement detail view with live socket, timeline, and panels"
```

---

### Task 9: HitLModal + AttackGraph

**Files:**
- Create: `frontend/src/components/HitLModal.tsx`, `frontend/src/components/HitLModal.module.css`, `frontend/src/components/AttackGraph.tsx`, `frontend/src/components/AttackGraph.module.css`
- Test: `frontend/src/components/HitLModal.test.tsx`, `frontend/src/components/AttackGraph.test.tsx`

**Interfaces:**
- Consumes: `summary.pending_hitl_gates` (sticky re-render source, spec §7.1), `events` (gate frames with `gate_id`), `resolveHitl` from `api.ts`.
- Produces: nothing downstream.

- [ ] **Step 1: Implement HitLModal**

```tsx
// frontend/src/components/HitLModal.tsx
import { useEffect, useState } from "react";
import { resolveHitl } from "../api";
import type { EventFrame } from "../socket";
import type { HitlGate, StateSummary } from "../types";
import styles from "./HitLModal.module.css";

interface Props {
  engagementId: string;
  summary: StateSummary;
  events: EventFrame[];
}

export default function HitLModal({ engagementId, summary, events }: Props) {
  // Live gate frames win (they carry command preview); pending list from the
  // state summary keeps the modal sticky across reconnects (spec §7.1).
  const gateFromEvent = events.find((f) => f.event.type === "hitl_gate");
  const pending: HitlGate[] = gateFromEvent
    ? [{
        gate_id: String(gateFromEvent.event.gate_id),
        gate_type: String(gateFromEvent.event.gate_type ?? "gate"),
        target: String(gateFromEvent.event.target ?? ""),
        command: String(gateFromEvent.event.command ?? ""),
        risks: (gateFromEvent.event.risks as string[]) ?? [],
      }]
    : summary.pending_hitl_gates;

  const [error, setError] = useState<string | null>(null);
  const [decided, setDecided] = useState<string | null>(null);

  useEffect(() => { setDecided(null); setError(null); }, [pending[0]?.gate_id]);

  if (pending.length === 0) return null;
  const gate = pending[0];

  async function decide(approved: boolean) {
    try {
      await resolveHitl(engagementId, gate.gate_id, approved);
      setDecided(approved ? "approved" : "rejected");
    } catch (e) {
      if (String(e).includes("already-resolved")) {
        setDecided("already resolved by another operator");
      } else {
        setError(String(e));
      }
    }
  }

  return (
    <div className={styles.overlay} role="dialog" aria-label="HitL approval">
      <div className={styles.modal}>
        <h3>⚠ Approval required — {gate.gate_type}</h3>
        <p>target: {gate.target}</p>
        <pre className={styles.cmd}>{gate.command || "(no command preview)"}</pre>
        {gate.risks.length > 0 && (
          <ul className={styles.risks}>
            {gate.risks.map((r, i) => <li key={i}>{r}</li>)}
          </ul>
        )}
        {error && <p className={styles.err}>{error}</p>}
        {decided ? (
          <p className={styles.decided}>{decided}</p>
        ) : (
          <div className={styles.buttons}>
            <button className={styles.approve} onClick={() => void decide(true)}>Approve</button>
            <button className={styles.reject} onClick={() => void decide(false)}>Reject</button>
          </div>
        )}
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Implement AttackGraph**

```tsx
// frontend/src/components/AttackGraph.tsx
import {
  Background, Controls, ReactFlow, type Edge, type Node,
} from "@xyflow/react";
import { useMemo } from "react";
import type { StateSummary } from "../types";
import "@xyflow/react/dist/style.css";
import styles from "./AttackGraph.module.css";

export default function AttackGraph({ summary }: { summary: StateSummary }) {
  const { nodes, edges } = useMemo(() => {
    const ips = new Set<string>(summary.target_scope);
    for (const h of summary.hosts) ips.add(h.ip);
    for (const f of summary.footholds) ips.add(f.host_ip);
    for (const m of summary.movement_paths) { ips.add(m.from_host); ips.add(m.to_host); }

    const footholdIps = new Set(summary.footholds.map((f) => f.host_ip));
    const pivotTargets = new Set(summary.pivots.map((p) => (p as { target_host: string }).target_host));

    const nodes: Node[] = [...ips].map((ip, i) => ({
      id: ip,
      position: { x: 80 + (i % 4) * 220, y: 80 + Math.floor(i / 4) * 120 },
      data: { label: ip },
      style: {
        background: footholdIps.has(ip) ? "#166534" : "#3f3f46",
        color: "#f4f4f5", border: pivotTargets.has(ip) ? "2px solid #f59e0b" : "1px solid #71717a",
        borderRadius: 8,
      },
    }));
    const edges: Edge[] = summary.movement_paths.map((m, i) => ({
      id: `e${i}`, source: m.from_host, target: m.to_host,
      label: m.method, animated: true, style: { stroke: "#f59e0b" },
    }));
    return { nodes, edges };
  }, [summary]);

  if (summary.movement_paths.length === 0) {
    return <p className={styles.empty}>No movement yet — the graph appears after the first pivot.</p>;
  }
  return (
    <div className={styles.canvas}>
      <ReactFlow nodes={nodes} edges={edges} fitView>
        <Background />
        <Controls />
      </ReactFlow>
    </div>
  );
}
```

Add the tab to `DataPanels.tsx`: extend `TABS` with `"Attack Graph"` and render `<AttackGraph summary={summary} />` for it (import from `./AttackGraph`). Import `MovementPath` typing for pivots stays `unknown` cast as shown.

**Wire the modal into the detail view** — the edit to `frontend/src/views/EngagementDetail.tsx` (created in Task 8 without the modal):

```tsx
// add to the import block:
import HitLModal from "../components/HitLModal";

// add as the last child inside the root <div className={styles.page}>,
// after the {roe && <RoeCard roe={roe} />} line:
      <HitLModal engagementId={id} summary={summary} events={events} />
```

CSS modules:

```css
/* frontend/src/components/HitLModal.module.css */
.overlay { position: fixed; inset: 0; background: rgba(0, 0, 0, 0.7); display: flex; align-items: center; justify-content: center; z-index: 50; }
.modal { background: #1c1c1f; border: 1px solid #b45309; border-radius: 10px; padding: 1.25rem 1.5rem; max-width: 34rem; width: 90%; color: #d4d4d8; font-family: system-ui, sans-serif; }
.modal h3 { margin: 0 0 0.75rem; color: #fbbf24; }
.cmd { background: #18181b; border: 1px solid #3f3f46; border-radius: 6px; padding: 0.5rem 0.75rem; overflow-x: auto; font-size: 0.8rem; }
.risks { color: #f87171; font-size: 0.85rem; }
.err { color: #f87171; font-size: 0.85rem; }
.decided { color: #4ade80; font-weight: 600; }
.buttons { display: flex; gap: 0.75rem; margin-top: 1rem; }
.buttons button { flex: 1; padding: 0.5rem 0; border: none; border-radius: 6px; font-weight: 700; cursor: pointer; }
.approve { background: #166534; color: #dcfce7; }
.reject { background: #991b1b; color: #fee2e2; }
```

```css
/* frontend/src/components/AttackGraph.module.css */
.canvas { height: 24rem; border: 1px solid #3f3f46; border-radius: 8px; }
.empty { color: #52525b; font-size: 0.8rem; padding: 1rem; }
```

- [ ] **Step 3: Write the failing tests, then run**

```tsx
// frontend/src/components/HitLModal.test.tsx
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { StateSummary } from "../types";
import HitLModal from "./HitLModal";

const resolveHitl = vi.fn();
vi.mock("../api", () => ({
  resolveHitl: (...args: unknown[]) => resolveHitl(...args),
}));

const baseSummary = {
  pending_hitl_gates: [],
} as unknown as StateSummary;

const gateEvent = {
  seq: 12,
  event: {
    type: "hitl_gate", gate_id: "12", gate_type: "exploit",
    target: "10.0.0.1", command: "msfconsole -x eternalblue",
    risks: ["crashes host"],
  },
};

describe("HitLModal", () => {
  beforeEach(() => resolveHitl.mockReset());

  it("renders gate fields from the event frame and posts approve", async () => {
    resolveHitl.mockResolvedValue(undefined);
    render(
      <HitLModal engagementId="eng_1" summary={baseSummary} events={[gateEvent]} />,
    );
    expect(screen.getByText(/msfconsole -x eternalblue/)).toBeTruthy();
    expect(screen.getByText("crashes host")).toBeTruthy();
    await userEvent.click(screen.getByText("Approve"));
    await waitFor(() =>
      expect(resolveHitl).toHaveBeenCalledWith("eng_1", "12", true),
    );
  });

  it("closes with a note on 409 (already resolved)", async () => {
    resolveHitl.mockRejectedValue(new Error("already-resolved"));
    render(
      <HitLModal engagementId="eng_1" summary={baseSummary} events={[gateEvent]} />,
    );
    await userEvent.click(screen.getByText("Reject"));
    await waitFor(() =>
      expect(screen.getByText(/already resolved/)).toBeTruthy(),
    );
  });

  it("renders nothing when no gate is pending", () => {
    const { container } = render(
      <HitLModal engagementId="eng_1" summary={baseSummary} events={[]} />,
    );
    expect(container).toBeEmptyDOMElement();
  });
});
```

```tsx
// frontend/src/components/AttackGraph.test.tsx
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { StateSummary } from "../types";
import AttackGraph from "./AttackGraph";

vi.mock("@xyflow/react", async (importOriginal) => ({
  ...(await importOriginal<object>()),
  ReactFlow: ({ nodes, edges }: { nodes: unknown[]; edges: unknown[] }) => (
    <div data-testid="rf">{nodes.length} nodes {edges.length} edges</div>
  ),
  Background: () => null,
  Controls: () => null,
}));

const summary = {
  target_scope: ["10.0.0.1"],
  hosts: [{ ip: "10.0.0.2", hostname: null, os: null }],
  footholds: [],
  pivots: [],
  movement_paths: [
    { from_host: "10.0.0.1", to_host: "10.0.0.2", method: "wmiexec", credential_used: "s1" },
  ],
} as unknown as StateSummary;

describe("AttackGraph", () => {
  it("renders placeholder before any movement", () => {
    render(<AttackGraph summary={{ ...summary, movement_paths: [] } as StateSummary} />);
    expect(screen.getByText(/No movement yet/)).toBeTruthy();
  });

  it("renders nodes and labelled edges from movement_paths", () => {
    render(<AttackGraph summary={summary} />);
    expect(screen.getByTestId("rf")).toHaveTextContent("2 nodes 1 edges");
  });
});
```

Add `userEvent` dependency: `npm --prefix frontend install -D @testing-library/user-event@^14.5.0`.

Run: `npm --prefix frontend run test`
Expected: PASS (all files: 3 + 2 + earlier).

- [ ] **Step 4: Build the SPA and commit**

Run: `npm --prefix frontend run build`
Expected: `dist/` produced, `tsc` clean.

```bash
git add frontend/src
git commit -m "feat: hitl approval modal and react-flow attack graph"
```

---

### Task 10: Static Serving + No-Build Fallback + README

**Files:**
- Modify: `autored/dashboard/api.py` (`create_app` gains static mount + fallback)
- Modify: `README.md` (new "Dashboard" section)
- Test: `tests/unit/dashboard/test_api.py` (append)

**Interfaces:**
- Consumes: everything prior. No new produces.

- [ ] **Step 1: Write the failing tests (append)**

```python
@pytest.mark.asyncio
async def test_root_falls_back_without_build(engagement_dir, client):
    # dist/ doesn't exist in the repo checkout → instruction page
    resp = await client.get("/")
    assert resp.status_code == 200
    assert "npm --prefix frontend run build" in resp.text


@pytest.mark.asyncio
async def test_root_serves_spa_when_built(engagement_dir, tmp_path, monkeypatch, client):
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<html>SPA</html>")
    monkeypatch.setattr("autored.dashboard.api.FRONTEND_DIST", dist)
    resp = await client.get("/")
    assert "SPA" in resp.text
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/dashboard/test_api.py -k root -v`
Expected: FAIL — `/` is 404.

- [ ] **Step 3: Implement static mount + fallback**

In `autored/dashboard/api.py`, module level:

```python
FRONTEND_DIST = Path("frontend") / "dist"
```

Inside `create_app()`, after the other routes:

```python
        from fastapi.responses import HTMLResponse, PlainTextResponse
        from fastapi.staticfiles import StaticFiles

        dist = FRONTEND_DIST if FRONTEND_DIST.is_dir() else None
        if dist is not None:
            app.mount("/", StaticFiles(directory=str(dist), html=True), name="spa")
        else:
            @app.get("/", include_in_schema=False)
            async def no_build() -> PlainTextResponse:
                return PlainTextResponse(
                    "Dashboard SPA not built. Run: npm --prefix frontend run build\n"
                    "API and WebSocket remain available at /api/* and /ws/*.\n",
                )
```

Ordering note: the catch-all mount must be added **last** in `create_app` so `/api/*` and `/ws` routes win. If the mount shadows anything, guard the mount behind `dist is not None` as shown (when built, StaticFiles' `html=True` serves `index.html` for `/` only; API routes registered before still take precedence in Starlette).

- [ ] **Step 4: Run tests + full suites + README**

Run: `uv run pytest tests/unit/dashboard/ -v && uv run pytest -q && npm --prefix frontend run test`
Expected: green everywhere.

README section (insert after the "TUI keybindings" section):

```markdown
## Dashboard (live ops console)

Watch a running engagement and approve HitL gates from a browser:

```bash
# one-time: build the SPA
npm --prefix frontend install
npm --prefix frontend run build

# run with the dashboard served on 127.0.0.1:8500
autored run --target 192.168.56.22 --roe roe-sandbox.yaml --dashboard
# open http://127.0.0.1:8500
```

- `--dashboard` and `--tui` are mutually exclusive (both consume the
  same EventBus queue).
- The dashboard is localhost-only by design; it displays harvested
  credentials and approves actions.
- Without a frontend build, `--dashboard` still serves the API and WS
  and prints the build instruction at `/`.
```

- [ ] **Step 5: Commit**

```bash
git add autored/dashboard/api.py tests/unit/dashboard/test_api.py README.md
git commit -m "feat: serve built dashboard spa with no-build fallback and docs"
```

---

## Ship Criteria (spec §11 verification)

| # | Criterion | Proven by |
|---|---|---|
| 1 | `--dashboard` serves SPA + run proceeds headless-equivalent | Task 6 tests + manual run |
| 2 | Live phase transitions without reload | Task 8 socket tests + Task 4 state-frame tests |
| 3 | HitL modal → approve unblocks `wait_for_tui_response()` | Task 5 `test_hitl_post_resolves_pending_gate` (contract), Task 9 (UI) |
| 4 | `--tui --dashboard` rejected | Task 1 |
| 5 | Evidence traversal refused | Task 3 |
| 6 | Secrets never in event frames | Task 4 `test_secret_values_scrubbed_from_event_frames` |
| 7 | Backend + frontend suites green | Tasks 1-10 `uv run pytest -q` / `npm test` |
| 8 | Server crash doesn't abort run | Task 6 `test_supervised_server_survives_crash` |
