# AutoRed Dashboard — Live Ops Console Design Spec

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. An implementation plan will be written to `docs/superpowers/plans/2026-09-27-autored-dashboard.md` before implementation begins.

**Goal:** A browser-based live ops console for AutoRed: watch a running engagement's kill chain in real time and approve Human-in-the-Loop (HitL) gates from a web UI, instead of keeping a terminal with the TUI open.

**Stack:** FastAPI (in-process) serving a Vite + React + TypeScript SPA over a WebSocket event bridge tapped into the existing `EventBus`. Localhost-only, no auth.

---

## 1. Scope

### 1.1 In Scope

- `autored run --dashboard` flag that starts a dashboard server alongside the orchestrator (same run model as `--tui`).
- REST API: engagement list, per-engagement state, evidence file viewing, HitL gate resolution.
- WebSocket stream of live orchestrator events (phase changes, agent status, tool calls, HitL gates) + periodic state snapshots.
- React SPA: EngagementList home screen, EngagementDetail ops view (phase timeline, activity log, findings/secrets/hosts tabs, state inspector, attack graph), HitL approval modal.
- Attack graph rendered with `react-flow` from `hosts` + `movement_paths` + `pivots` state.
- Backend tests (pytest + httpx) and frontend smoke tests (vitest).

### 1.2 Out of Scope

- Launching engagements from the browser (start stays in the CLI).
- Any network exposure beyond localhost — no auth, no TLS, no token.
- Cross-process attach: a run started without `--dashboard` cannot be attached to later.
- Editing RoE from the browser (read-only RoE display only).
- Report rendering in the browser (existing `report.md`/`report.pdf` open via evidence viewer).
- Mobile-specific layouts (responsive enough not to break, not a target).

---

## 2. Run Model & Frontend Selection Constraint

`autored run --dashboard` constructs the `EventBus` (as `--tui` does), passes it to the graph, and additionally starts a uvicorn server as an in-process asyncio task serving the SPA + API + WS. The server task is supervised: if it crashes, the orchestrator run continues headless (same isolation contract as `--tui`).

**Single-frontend constraint (important):** the `EventBus.orchestrator_to_tui` queue is a single-consumer channel. The TUI drains it via `try_get_tui_event()`; the dashboard bridge drains it the same way. Running `--tui` and `--dashboard` simultaneously is **not supported** — events would be split arbitrarily between the two consumers. The CLI must reject `--tui --dashboard` together with a clear error. HitL resolution writes to `tui_to_orchestrator` via `emit_to_orchestrator`, so either frontend unblocks the node; "first responder wins" is the documented behaviour if someone bypasses the CLI check.

---

## 3. Architecture

```
┌────────────────────────────────────────────────────────────────┐
│ CLI (Typer)                                                     │
│   autored run --target <ip> --roe <yaml> --dashboard            │
│   └── rejects --tui --dashboard (single-frontend constraint)    │
└──────────────┬─────────────────────────────────────────────────┘
               ▼
┌──────────────────────────────┐    ┌────────────────────────────┐
│ LangGraph orchestrator       │    │ Dashboard server (in-proc) │
│   graph nodes                │    │   FastAPI + uvicorn task   │
│   EventBus (existing)        │◄──►│   WS bridge  REST endpoints│
│     orchestrator_to_tui  ────┼───►│   SPA static mount         │
│     tui_to_orchestrator  ◄───┼────│   POST /hitl resolves gate │
└──────────────────────────────┘    └──────────┬─────────────────┘
                                               ▼  http://127.0.0.1:8500
                                    ┌────────────────────────────┐
                                    │ React SPA (Vite build)     │
                                    │  EngagementList            │
                                    │  EngagementDetail          │
                                    │  HitLModal                 │
                                    └────────────────────────────┘
```

The bridge is a thin adapter (`autored/dashboard/bridge.py`): it polls `orchestrator_to_tui` (same pattern as the TUI's widget loop), serialises each event dict to JSON, and fans it out to all connected WS clients for the engagement. No changes to the orchestrator, agents, RoE Guard, or models.

---

## 4. WebSocket Protocol (`WS /ws/{engagement_id}`)

All frames are JSON objects with a `type` discriminator.

**Server → client:**

| `type` | Payload | Emitted when |
|---|---|---|
| `hello` | `{engagement_id, seq, state_summary}` | On WS connect (initial sync), followed immediately by replayed `event` frames from the ring buffer (§8) carrying their original `seq` values |
| `event` | `{seq, event: <raw EventBus dict>}` | Each drained `orchestrator_to_tui` event |
| `state` | `{seq, state_summary}` | Periodic (every 5 s) and after each `event` whose `type` is `phase_change` |
| `ping` | `{ts}` | Every 15 s (client replies with any frame; no pong tracking — reconnect handles staleness) |

`seq` is a monotonically increasing integer per engagement; the ring buffer stores each event under the `seq` it was emitted with, so late joiners can detect gaps during replay.

`state_summary` is `EngagementState.model_dump()` restricted to display fields: `phase`, `engagement_id`, `target_scope`, `hosts`, `services`, `findings`, `footholds`, `harvested_secrets`, `pivots`, `movement_paths`, `sub_engagements`, `cleanup_results`, `attack_hypotheses` (counts only for large lists — see §6), plus `pending_hitl_gates` (the bridge's currently-unresolved gate summaries — this is what makes the HitLModal sticky across reconnects, §7.1).

**Client → server:** only `{"type": "ping"}` is defined. HitL decisions go over REST (§5), not WS, so gate resolution is request/response and testable.

---

## 5. REST API Contract

All endpoints are mounted under the dashboard server on `127.0.0.1:8500` (port overridable via `--dashboard-port`).

| Method | Path | Returns | Errors |
|---|---|---|---|
| `GET` | `/api/engagements` | `[{engagement_id, target, phase, started_at, status}]` — from `db/engagements.sqlite`; filesystem fallback via `engagements/<id>/manifest.json` (same logic as the CLI) | `[]` when none |
| `GET` | `/api/engagements/{id}/state` | Full `state_summary` (§4 shape) from `engagements/<id>/state.json` | `404` unknown id |
| `GET` | `/api/engagements/{id}/evidence/{path}` | File bytes with content-type guessed | `404` missing, `400` path escape |
| `GET` | `/api/engagements/{id}/roe` | The engagement's `RulesOfEngagement` dump (read-only display) | `404` |
| `POST` | `/api/engagements/{id}/hitl/{gate_id}` | Body `{approved: bool, note?: str}` → `200 {status: "resolved"}` | `409` gate already resolved / unknown gate; `404` engagement not live |

**Evidence path jail:** the `{path}` component is resolved against `engagements/<id>/evidence/` and rejected (HTTP 400) if the resolved path escapes that directory (symlinks resolved too — `Path.resolve()` + prefix check).

**HitL resolution semantics:** the bridge keeps `{gate_id: pending}` populated as `hitl_gate` events are drained. `POST /hitl/{gate_id}` validates the gate exists and is unresolved, then calls `bus.emit_to_orchestrator({"type": "hitl_response", "gate_id": gate_id, "approved": ..., "note": ...})` — the exact dict shape the orchestrator's `wait_for_tui_response()` consumer expects. The pending entry is marked resolved before emitting (idempotency: a second POST returns `409` with the recorded decision).

---

## 6. Data Volume & Redaction Rules

- `harvested_secrets` are shown **verbatim** in the Secrets tab. Rationale: the dashboard is localhost-only (threat model: the operator's own machine) and an ops console that hides credential values forces a second tool. Secret values must never appear in log lines broadcast over WS — only in the Secrets tab fed by the `state` snapshot.
- Lists that can grow large (`findings`, `attack_hypotheses`, `harvested_secrets`) are sent as counts inside `state_summary` when length > 200, with full rows fetched on demand via `GET /api/engagements/{id}/state` (which returns full rows — the count-cap applies only to WS frames).

---

## 7. Frontend (Vite + React + TypeScript)

Lives in `frontend/` at the repo root. Built artifact (`frontend/dist/`) is served by FastAPI's `StaticFiles` at `/`. `dist/` is gitignored; `autored run --dashboard` without a build falls back to log-only mode and prints the build instruction.

### 7.1 Views

**EngagementList (route `/`)** — table of engagements from `GET /api/engagements`: id, target, phase badge, status (running / done / failed / unknown), started_at. A running engagement links to its detail view. Polls every 10 s (no WS on this screen — keep it stateless).

**EngagementDetail (route `/engagements/{id}`)** — the ops view, four zones:

1. **PhaseTimeline** (top bar) — `recon → vuln → exploit → postex → lateral → cleanup → report → done`, active phase highlighted from WS `state` frames; completed phases get a check, failed phases get a red marker.
2. **ActivityLog** (left column) — reverse-chronological feed of WS `event` frames: timestamp, source node, one-line summary (event dicts carry `type`, `node`, `message`/`tool`; unknown event types render their JSON).
3. **Right column tabbed panels**:
   - **Findings** — table from state snapshot (`title`, `severity`, `host`).
   - **Secrets** — table of `harvested_secrets` (`secret_type`, `source`, `secret_value` verbatim, §6).
   - **Hosts & Footholds** — hosts with their services and any footholds (`host_ip`, `method`, `access_type`).
   - **AttackGraph** — `react-flow` DAG: nodes = hosts (+ the operator node), edges = `movement_paths` (labelled with `method`), pivots highlighted, footholds marked. Empty until `movement_paths` exist; renders a placeholder otherwise.
   - **StateInspector** — collapsible JSON tree of the full state summary (last `state` frame).
   - **RoE** — read-only card of the engagement's RoE from `GET .../roe`.
4. **HitLModal** — when an `event` frame of type `hitl_gate` arrives: modal with action, risk note, target, and command preview (fields per the existing `hitl_gate` event payload), plus Approve / Reject buttons posting to `/api/engagements/{id}/hitl/{gate_id}`. On `409` the modal closes and the log shows the already-recorded decision. Modal is sticky (re-renders after reconnect if the gate is still pending in the latest `state` frame).

### 7.2 Frontend mechanics

- One `useEngagementSocket(id)` hook owns the WS lifecycle: connect, `hello` → seed state, frames → update a reducer store, exponential backoff reconnect (1 s → 2 s → 4 s → … cap 30 s), on reconnect re-sync from `GET .../state`.
- Styling: plain CSS modules (no Tailwind) — the SPA has ~6 components; a utility framework is not worth the build weight.
- Router: `react-router`; state: `useReducer` + context (no Redux/Zustand — nothing warrants it).

---

## 8. Error Handling

| Failure | Behaviour |
|---|---|
| Dashboard server task raises | Caught by the CLI supervisor; logged; orchestrator continues headless |
| WS client disconnects | Bridge removes the socket from the fan-out set; no backpressure (events are drained from the bus regardless of connected clients — the bridge keeps the last 500 events in a ring buffer and replays them on `hello` with `seq` so late joiners get history) |
| `GET .../state` on a never-started id | `404` with a JSON error body; SPA shows a not-found card |
| HitL POST for an unknown/resolved gate | `409` with the recorded decision (or `404` if the engagement has no live bridge) |
| Evidence path traversal | `400`; attempt is logged server-side |
| SPA not built | Server starts, `/` returns a plain-text instruction page (`npm --prefix frontend run build`), API + WS still work |
| `--tui --dashboard` together | CLI exits with a usage error before the run starts (§2) |

---

## 9. Testing

**Backend (pytest, mirrors existing suite patterns):**

- `tests/unit/dashboard/test_api.py` — engagement list (SQLite-backed + filesystem fallback), state endpoint (full rows), evidence path jail (traversal + symlink rejected, valid file served), RoE endpoint, `--tui --dashboard` CLI rejection.
- `tests/unit/dashboard/test_bridge.py` — fake `EventBus`: events drained → WS frames with correct `type`/`seq`; ring-buffer replay on `hello`; secret values never appear in `event` frames (§6 redaction).
- `tests/integration/test_dashboard_hitl.py` — full loop with a fake pending gate: bridge registers gate → POST approve → `wait_for_tui_response()` returns the response dict; second POST → `409`; reject path → response carries `approved: false`.

httpx `AsyncClient` with ASGI transport drives all endpoints; WS frames asserted via the bridge's fan-out API (a registered fake socket) rather than a live WS client.

**Frontend (vitest, smoke level):**

- EngagementList renders rows from mocked API and links running engagements.
- HitLModal renders gate fields, posts approve/reject, closes on `409`.
- `useEngagementSocket` reconnect + re-sync on dropped socket (mocked WS).

The attack graph is contract-tested on the backend (state shape) — the SPA component gets a render smoke test only.

---

## 10. Repository Layout & Tooling

```
autored/
├── autored/dashboard/
│   ├── __init__.py
│   ├── server.py          # FastAPI app factory + StaticFiles mount
│   ├── api.py             # REST endpoints (§5)
│   ├── bridge.py          # EventBus → WS fan-out, ring buffer, gate registry
│   └── cli.py             # --dashboard flag wiring in autored/cli.py (not a new command)
├── frontend/              # NEW top-level (Vite project root)
│   ├── package.json       # vite, react, react-router, react-flow, vitest
│   ├── src/
│   │   ├── App.tsx  api.ts  socket.ts
│   │   ├── views/  EngagementList.tsx  EngagementDetail.tsx
│   │   ├── components/  PhaseTimeline  ActivityLog  FindingsPanel
│   │   │    SecretsPanel  HostsPanel  AttackGraph  StateInspector
│   │   │    RoeCard  HitLModal
│   │   └── styles/  *.module.css
│   └── dist/              # gitignored build output
├── tests/unit/dashboard/  # backend tests (§9)
└── pyproject.toml         # + fastapi, uvicorn (pinned)
```

- `pyproject.toml`: add `fastapi==0.115.*` and `uvicorn==0.32.*` (pinned, matching the repo's pin-everything convention).
- `frontend/dist/` and `node_modules/` gitignored.
- README: new "Dashboard" section (build steps, run command, screenshots placeholder).

---

## 11. Ship Criteria

1. `autored run --target <ip> --roe <yaml> --dashboard` serves the SPA on `127.0.0.1:8500` and the run proceeds identically to a headless run.
2. Engagement list and detail views render live phase transitions for a mocked (integration-test) engagement without page reload.
3. A HitL gate emitted by the orchestrator pops the modal; clicking Approve unblocks the graph node (integration test proves the `wait_for_tui_response()` contract).
4. `--tui --dashboard` is rejected with a clear CLI error.
5. Evidence viewer refuses path traversal (unit test).
6. Secret values never appear in WS `event` frames (unit test).
7. Backend: all new pytest tests pass; full suite green. Frontend: vitest suite green; `npm run build` succeeds.
8. Dashboard server crash mid-run does not abort the orchestrator (unit test with a raising server task).
