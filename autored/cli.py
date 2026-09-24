"""AutoRed Typer CLI — Phase 6 entry point.

Ships the original Phase 1 commands (``run``, ``resume``,
``engagements``, ``version``, ``roe-wizard``) plus the Phase 6
reporting / inspection commands (``report``, ``state``). The CLI is
the single entry point invoked by the ``autored`` console-script
defined in ``pyproject.toml``'s ``[project.scripts]`` block.

The ``run`` command orchestrates a full Phase 6 LangGraph engagement
end-to-end (RoE load → engagement-id mint → folder init → checkpointer
→ ``build_phase6_graph`` → ``ainvoke`` → state save). Phase 6 closes
the kill chain at last: the real Report Agent (Task 9, ``report_node``)
replaces the ``report_phase1`` stub, so every engagement ends in
generated deliverables (report.md + report.pdf + lessons.json) and
cross-engagement memory persistence.

Phase 6 also delivers the full ``resume`` command (the Phase 1 TODO
finally paid): re-register RoE, wire a fresh EventBus, build the
Phase 6 graph with the engagement's checkpointer, try checkpoint-resume
(``ainvoke(None, config={"thread_id": ...})`` — continues from the
last persisted checkpoint), fall back to re-invoking with the loaded
state when no checkpoint history exists. The ``report`` command runs
the Report Agent against a saved engagement's state and prints the
deliverable paths; ``state`` prints a Rich Table of every state
collection's count; ``engagements`` lists from SQLite
(``db/engagements.sqlite``) with a filesystem fallback (spec §14.2).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    name="autored",
    help="AutoRed — Autonomous Red Team Copilot",
    no_args_is_help=True,
)
console = Console()


async def _close_checkpointer(checkpointer) -> None:
    """Best-effort close of the checkpointer's underlying DB connection.

    The real ``AsyncSqliteSaver`` exposes an ``aiosqlite.Connection`` as
    ``checkpointer.conn`` whose ``close()`` is a coroutine function.
    Test mocks (``MagicMock()``) return a plain MagicMock from
    ``conn.close()`` — awaiting that raises ``TypeError("object
    MagicMock can't be used in 'await' expression")``.

    Defensive handling: call ``conn.close()``, then ``await`` the
    result only when it's actually a coroutine. Catches and ignores
    any other exception so a close failure can never break the
    surrounding ``finally`` block.
    """
    conn = getattr(checkpointer, "conn", None)
    if conn is None or not hasattr(conn, "close"):
        return
    try:
        close_result = conn.close()
        if asyncio.iscoroutine(close_result):
            await close_result
    except Exception:  # noqa: BLE001 — best-effort close, never raise
        pass


@app.command()
def run(
    target: str = typer.Option(..., "--target", "-t", help="Target IP, CIDR, or hostname"),
    roe: str = typer.Option(..., "--roe", "-r", help="Path to RoE YAML file"),
    name: str = typer.Option("", "--name", "-n", help="Engagement name"),
    tui: bool = typer.Option(
        False,
        "--tui/--no-tui",
        help="Launch TUI (Phase 3+). Default is headless.",
    ),
) -> None:
    """Start a new engagement (headless LangGraph run)."""
    from autored.config import load_roe
    from autored.graph import build_phase6_graph
    from autored.logging import get_logger, setup_logging
    from autored.persistence.filesystem import (
        init_engagement_folder,
        save_state_to_disk,
    )
    from autored.persistence.sqlite_saver import make_checkpointer
    from autored.roe_guard import register_roe
    from autored.state import EngagementState
    from autored.utils import generate_engagement_id

    setup_logging()
    log = get_logger("cli")

    roe_config = load_roe(roe)
    engagement_id = generate_engagement_id(target, name)

    console.print(f"[bold green]Starting engagement:[/] {engagement_id}")
    console.print(f"  Target: {target}")
    console.print(f"  RoE: {roe}")
    console.print(f"  Operator: {roe_config.operator}")

    # Register RoE for guard
    register_roe(engagement_id, roe_config)

    # Init engagement folder
    init_engagement_folder(engagement_id, target, roe_config.operator)

    log.info("engagement_start", engagement_id=engagement_id, target=target)

    # --tui branch (Phase 6 Task 12): build the RunConfig, print the
    # banner, and hand off to ``AutoRedApp.run()``. The orchestrator
    # runs as an ``asyncio.create_task`` on the app's event loop (spec
    # §14.2: "Orchestrator runs in background thread/task") so the
    # EventBus queues are shared without cross-thread synchronisation
    # and Pilot can ``await`` the task directly in tests for
    # deterministic completion. ``app.run()`` blocks until the operator
    # presses ``q`` — the action_quit handler cancels the orchestrator
    # task before ``self.exit()`` so the checkpointer's SQLite handle is
    # closed cleanly by ``_run_orchestrator``'s ``finally`` block.
    # Spec deviation note: the CLI's headless path keeps the
    # ``register_roe`` + ``init_engagement_folder`` calls; the app's
    # ``_mount_fresh_engagement`` calls them again (idempotent —
    # ``register_roe`` overwrites the registry, ``init_engagement_folder``
    # uses ``mkdir(parents=True, exist_ok=True)``), so the duplicate is
    # harmless and keeps the launch path identical to the headless one
    # for the headless-only smoke tests.
    if tui:
        from autored.tui.app import AutoRedApp, RunConfig

        console.print(f"[bold green]Launching TUI:[/] {engagement_id}")
        app_tui = AutoRedApp(
            engagement_id=engagement_id,
            run_config=RunConfig(
                target=target,
                roe_path=roe,
                engagement_id=engagement_id,
                operator=roe_config.operator,
            ),
        )
        app_tui.run()  # blocks until the operator quits
        return

    # Initialize state (headless path only — the TUI branch returns
    # above so this construction is unreachable when ``--tui`` is set).
    state = EngagementState(
        engagement_id=engagement_id,
        target_scope=[target],
        operator=roe_config.operator,
        rules_of_engagement=roe_config,
    )

    async def _run() -> object:
        checkpointer = await make_checkpointer(engagement_id)
        try:
            graph = build_phase6_graph(checkpointer)
            # I1 (Phase 3 fix wave): EventBus travels via RunnableConfig
            # rather than a non-Pydantic state attribute. LangGraph's
            # reducer strips `__pydantic_extra__` (where state.event_bus
            # lived under extra="allow"), so the previous
            # `state.event_bus = bus` pattern silently lost the bus
            # between CLI and exploit_node. The config dict is the
            # standard LangGraph channel for runtime objects (handles,
            # queues, connections) — it bypasses the reducer boundary.
            from autored.tui.event_bus import EventBus

            bus = EventBus()
            config = {
                "configurable": {
                    "thread_id": engagement_id,
                    "event_bus": bus,
                }
            }
            return await graph.ainvoke(state, config=config)
        finally:
            # Best-effort close so the SQLite file is flushed before the
            # state-disk save below reads it. ``make_checkpointer`` opens
            # the connection eagerly; we own its lifetime here. The
            # ``iscoroutine`` check guards against test mocks whose
            # ``conn.close()`` returns a non-awaitable MagicMock (the
            # real ``aiosqlite.Connection.close`` is async).
            await _close_checkpointer(checkpointer)

    try:
        final_state = asyncio.run(_run())
        # ``ainvoke`` may hand back either an ``EngagementState`` (pydantic
        # model) or a plain dict depending on the LangGraph version's
        # state-schema handling. Normalise to a model so
        # ``save_state_to_disk`` can call ``model_dump_json``.
        if isinstance(final_state, dict):
            final_state_model = EngagementState.model_validate(final_state)
        else:
            final_state_model = final_state
        save_state_to_disk(engagement_id, final_state_model)

        console.print(f"[bold green]Engagement complete:[/] {engagement_id}")
        console.print(f"  Phase: {final_state_model.phase}")
        console.print(f"  Hosts found: {len(final_state_model.hosts)}")
    except KeyboardInterrupt:
        console.print(
            f"\n[yellow]Interrupted. State saved. Resume with:[/] "
            f"autored resume {engagement_id}"
        )
        save_state_to_disk(engagement_id, state)
    except Exception as exc:  # noqa: BLE001 — top-level CLI error sink
        console.print(f"[bold red]Error:[/] {exc}")
        log.error("engagement_failed", engagement_id=engagement_id, error=str(exc))
        raise typer.Exit(code=1) from exc


@app.command()
def report(engagement_id: str) -> None:
    """Generate the report deliverables for a completed engagement.

    Runs the full Report Agent pipeline (exec summary, technical report,
    MITRE mapping, lessons, PDF when available) against the engagement's
    saved state and prints the deliverable paths. Missing state → clean
    error, exit code 1.
    """
    from autored.agents.report import report_node
    from autored.persistence.filesystem import load_state_from_disk
    from autored.roe_guard import register_roe

    console.print(f"[bold blue]Generating report:[/] {engagement_id}")
    state = load_state_from_disk(engagement_id)
    if state is None:
        console.print(f"[bold red]Error:[/] No state found for {engagement_id}")
        raise typer.Exit(code=1)

    register_roe(engagement_id, state.rules_of_engagement)

    async def _run() -> dict:
        # The Report Agent is full-auto (spec §2.4) — no EventBus needed
        # for HitL (there are none). Pass an empty config dict to keep
        # the two-arg signature uniform with the other nodes.
        return await report_node(state, config={"configurable": {}})

    result = asyncio.run(_run())

    # Merge the report result back into the state and persist it.
    # ``result`` is the state-dict patch from ``report_node`` (phase,
    # summary, lessons, mitre_mappings, report_paths, iteration_count).
    merged = state.model_dump()
    merged.update(result)
    from autored.persistence.filesystem import save_state_to_disk
    from autored.state import EngagementState

    save_state_to_disk(engagement_id, EngagementState.model_validate(merged))

    console.print(f"[bold green]Report complete:[/] {engagement_id}")
    console.print(f"  Markdown: {result['report_paths'].markdown_path}")
    console.print(
        f"  PDF: {result['report_paths'].pdf_path or '(unavailable — WeasyPrint/system libs missing)'}"
    )
    console.print(f"  Lessons: {result['report_paths'].lessons_path}")


@app.command()
def state(engagement_id: str) -> None:
    """Show an engagement's state summary (counts per collection)."""
    from autored.persistence.filesystem import load_state_from_disk

    loaded = load_state_from_disk(engagement_id)
    if loaded is None:
        console.print(f"[bold red]Error:[/] No state found for {engagement_id}")
        raise typer.Exit(code=1)

    table = Table(title=f"Engagement State — {engagement_id}")
    table.add_column("Field", style="cyan")
    table.add_column("Count / Value")
    table.add_row("Phase", loaded.phase)
    table.add_row("Iteration", str(loaded.iteration_count))
    table.add_row("Target", ", ".join(loaded.target_scope))
    table.add_row("Hosts", str(len(loaded.hosts)))
    table.add_row("Services", str(len(loaded.services)))
    table.add_row("Web apps", str(len(loaded.web_apps)))
    table.add_row("Vulnerabilities", str(len(loaded.vulnerabilities)))
    table.add_row("Attack hypotheses", str(len(loaded.attack_hypotheses)))
    table.add_row("Footholds", str(len(loaded.footholds)))
    table.add_row("Local users", str(len(loaded.local_users)))
    table.add_row("Harvested secrets", str(len(loaded.harvested_secrets)))
    table.add_row("Trust relationships", str(len(loaded.trust_relationships)))
    table.add_row("Privesc attempts", str(len(loaded.privesc_attempts)))
    table.add_row("Persistence artifacts", str(len(loaded.persistence_artifacts)))
    table.add_row("Evasion actions", str(len(loaded.evasion_actions)))
    table.add_row("Exfiltration proof", str(len(loaded.exfiltration_proof)))
    table.add_row("Pivots", str(len(getattr(loaded, "pivots", []))))
    table.add_row("Tunnels", str(len(getattr(loaded, "tunnels", []))))
    table.add_row("Sub-engagements", str(len(getattr(loaded, "sub_engagements", []))))
    table.add_row("Cleanup results", str(len(getattr(loaded, "cleanup_results", []))))
    table.add_row("Lessons", str(len(loaded.lessons)))
    table.add_row("MITRE mappings", str(len(loaded.mitre_mappings)))
    table.add_row("Errors", str(len(loaded.errors)))
    table.add_row("Evidence files", str(len(loaded.evidence_paths)))
    table.add_row("Summary", loaded.summary or "—")
    console.print(table)


@app.command()
def resume(engagement_id: str) -> None:
    """Resume an interrupted engagement from its last checkpoint.

    Prefers LangGraph checkpoint continuation (the engagement's own
    ``state.db``); falls back to re-invoking the graph with the saved
    ``state.json`` when no checkpoint history exists. The result is
    merged back into the loaded state (so partial dicts from the
    checkpoint-resume path validate against ``EngagementState``) and
    saved to disk either way.
    """
    from autored.persistence.filesystem import (
        load_state_from_disk,
        save_state_to_disk,
    )
    from autored.persistence.sqlite_saver import make_checkpointer
    from autored.roe_guard import register_roe

    console.print(f"[bold yellow]Resuming engagement:[/] {engagement_id}")
    state = load_state_from_disk(engagement_id)
    if state is None:
        console.print(f"[bold red]Error:[/] No state found for {engagement_id}")
        raise typer.Exit(code=1)

    register_roe(engagement_id, state.rules_of_engagement)
    console.print(f"  Last phase: {state.phase}")
    console.print(f"  Iteration: {state.iteration_count}")

    from autored.graph import build_phase6_graph
    from autored.tui.event_bus import EventBus

    async def _run():
        checkpointer = await make_checkpointer(engagement_id)
        try:
            graph = build_phase6_graph(checkpointer)
            # I1 (Phase 3 fix wave): EventBus travels via RunnableConfig
            # rather than a non-Pydantic state attribute. Mutating
            # ``state.event_bus = bus`` here would propagate into the
            # ``state.model_dump()`` call below, breaking the JSON
            # serializer (asyncio.Queue is not JSON-serialisable).
            bus = EventBus()
            config = {
                "configurable": {
                    "thread_id": engagement_id,
                    "event_bus": bus,
                }
            }
            try:
                # Checkpoint resume: None input = continue from last
                # checkpoint stored in the engagement's state.db.
                return await graph.ainvoke(None, config=config)
            except Exception:
                # No checkpoint history (or other ainvoke failure) —
                # re-invoke from the saved state.json instead.
                return await graph.ainvoke(state, config=config)
        finally:
            # Best-effort close (defensive against test mocks whose
            # ``conn.close()`` returns a non-awaitable MagicMock — see
            # ``_close_checkpointer`` for the real-vs-mock handling).
            await _close_checkpointer(checkpointer)

    try:
        final_state = asyncio.run(_run())
        # Merge the result back into the loaded state. ``final_state`` is
        # typically a full state dict (the normal LangGraph path), but
        # merge-with-loaded-state guards against partial dicts (e.g.,
        # when the mock lattice returns a stub ``{"phase": "done"}`` in
        # tests, or when a checkpoint-resume returns only the changed
        # fields). Without the merge, ``EngagementState.model_validate``
        # would fail on the required ``operator`` + ``rules_of_engagement``
        # fields. Mirrors the report command's persistence pattern.
        merged = state.model_dump()
        if isinstance(final_state, dict):
            merged.update(final_state)
        elif hasattr(final_state, "model_dump"):
            merged.update(final_state.model_dump())
        from autored.state import EngagementState

        final_state_model = EngagementState.model_validate(merged)
        save_state_to_disk(engagement_id, final_state_model)
        console.print(f"[bold green]Engagement complete:[/] {engagement_id}")
        console.print(f"  Phase: {final_state_model.phase}")
    except KeyboardInterrupt:
        console.print(
            f"\n[yellow]Interrupted. Resume again with:[/] autored resume {engagement_id}"
        )
        save_state_to_disk(engagement_id, state)

@app.command()
def engagements() -> None:
    """List all engagements (SQLite-backed, filesystem fallback).

    Tries ``db/engagements.sqlite`` first (the cross-engagement memory
    store written by ``persist_engagement_memory``); falls back to the
    filesystem scan of ``engagements/<id>/manifest.json`` when SQLite
    is unavailable (spec §14.2).
    """
    from autored.persistence.engagement_db import (
        init_db,
        list_engagements_with_findings,
    )

    rows: list[dict] | None = None
    try:

        async def _list():
            await init_db("db/engagements.sqlite")
            return await list_engagements_with_findings("db/engagements.sqlite")

        rows = asyncio.run(_list())
    except Exception as e:  # noqa: BLE001 — fall back to the filesystem scan
        console.print(f"[dim](SQLite unavailable: {e} — listing from filesystem)[/]")

    table = Table(title="Engagements")
    table.add_column("ID", style="cyan")
    table.add_column("Target")
    table.add_column("Phase")
    table.add_column("Started")
    table.add_column("Operator")

    if rows:
        for eng in rows:
            table.add_row(
                eng.get("id", ""),
                eng.get("target", ""),
                eng.get("phase", "—"),
                eng.get("start_ts", ""),
                eng.get("operator", ""),
            )
    else:
        from autored.persistence.filesystem import list_engagements

        for eng in list_engagements():
            table.add_row(
                eng.get("id", eng.get("engagement_id", "")),
                eng.get("target", ""),
                eng.get("phase", "—"),
                eng.get("started_at", ""),
                eng.get("operator", ""),
            )
    console.print(table)


@app.command()
def version() -> None:
    """Show version."""
    console.print("AutoRed v0.1.0 (Phase 1)")


@app.command()
def roe_wizard() -> None:
    """Interactive RoE file generator (spec §8.3).

    Full §8.3 verbatim flow via ``typer.prompt``: engagement name →
    operator → allowed IPs (comma-separated) → allowed techniques
    (``*`` or list) → persistence / evasion / exfiltration / kernel
    y-N prompts → hitl_mode choice → output path. Validates via the
    shared ``validate_roe_yaml`` (the same validator the TUI's
    RoEEditorScreen uses) before writing; on validation failure
    prints the errors and exits 1 so the operator sees the failure
    immediately rather than getting a broken file.
    """
    import yaml

    from autored.config import validate_roe_yaml

    console.print("[bold]AutoRed RoE Wizard[/]")
    engagement_name = typer.prompt("Engagement name")
    operator = typer.prompt("Operator name")
    allowed_ips = [
        ip.strip()
        for ip in typer.prompt("Allowed IPs (comma-separated)").split(",")
        if ip.strip()
    ]
    techniques_raw = typer.prompt("Allowed techniques (* for any)")
    allowed_techniques = [
        t.strip() for t in techniques_raw.split(",") if t.strip()
    ]
    persistence = typer.confirm("Allow persistence?", default=False)
    evasion = typer.confirm("Allow defense evasion?", default=False)
    exfiltration = typer.confirm("Allow data exfiltration?", default=False)
    kernel = typer.confirm("Allow kernel exploits?", default=False)
    hitl_mode = typer.prompt(
        "HitL mode (always_ask/auto_approve/disabled)",
        default="always_ask",
    )

    roe = {
        "engagement_name": engagement_name,
        "operator": operator,
        "operator_signature": f"wizard:{operator}",
        "allowed_ips": allowed_ips,
        "allowed_techniques": allowed_techniques,
        "persistence_allowed": persistence,
        "evasion_allowed": evasion,
        "exfiltration_allowed": exfiltration,
        "data_destruction_allowed": False,
        "kernel_exploits_allowed": kernel,
        "hitl_mode": hitl_mode,
    }

    # Spec §8.3 final validation — runs the same validator the TUI
    # RoEEditorScreen uses so a hand-built wizard result is exactly
    # as valid as an operator-edited one. Refuses to write on error
    # so the operator never ends up with a broken RoE file that
    # ``load_roe`` would reject at engagement start.
    errors = validate_roe_yaml(yaml.safe_dump(roe))
    if errors:
        console.print(f"[bold red]Generated RoE is invalid:[/] {errors}")
        raise typer.Exit(code=1)

    save_path = typer.prompt("Save to", default="roe-engagement.yaml")
    Path(save_path).write_text(yaml.safe_dump(roe, sort_keys=False))
    console.print(f"[bold green]RoE file saved to {save_path}[/]")


if __name__ == "__main__":
    app()
