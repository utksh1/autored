"""AutoRed command-line interface (Tasks 25-27).

Provides four Phase-1 commands plus one stub:

* ``run``         — start a new engagement (headless; TUI ships in Phase 3)
* ``resume``      — load an interrupted engagement's state from disk and
                    print where it stopped (full resume logic ships later)
* ``engagements`` — list every engagement folder on disk in a Rich table
* ``version``     — print the AutoRed version banner
* ``roe-wizard``  — stub: tells the operator to use ``roe-sandbox.yaml``
                    for lab work (full interactive wizard ships in Phase 6)

The ``run`` command's async path opens an ``AsyncSqliteSaver`` whose
underlying ``aiosqlite`` connection must be closed after the graph
finishes — we do that in a ``finally`` block so the connection is
released even if the run is interrupted or errors out.
"""

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="AutoRed — Autonomous Red Team Copilot")
console = Console()


# --------------------------------------------------------------------------- #
# run
# --------------------------------------------------------------------------- #
@app.command()
def run(
    target: str = typer.Option(..., "--target", "-t", help="Target IP, CIDR, or hostname"),
    roe: str = typer.Option(..., "--roe", "-r", help="Path to RoE YAML file"),
    name: str = typer.Option("", "--name", "-n", help="Engagement name"),
    tui: bool = typer.Option(False, "--tui/--no-tui", help="Launch TUI (Phase 3+)"),
):
    """Start a new engagement."""
    from autored.config import load_roe
    from autored.state import EngagementState
    from autored.roe_guard import register_roe
    from autored.utils import generate_engagement_id
    from autored.persistence.filesystem import (
        init_engagement_folder,
        save_state_to_disk,
    )
    from autored.persistence.sqlite_saver import make_checkpointer
    from autored.graph import build_phase4_graph
    from autored.logging import setup_logging, get_logger
    from autored.tui.event_bus import EventBus

    setup_logging()
    log = get_logger("cli")

    if tui:
        # Phase 3 ships a Textual TUI (DashboardScreen + HitLGateModal).
        # The headless path below is the default — when ``--tui`` is
        # passed we still wire an EventBus onto the state so the Exploit
        # Agent's HitL gates have somewhere to emit / block. The actual
        # Textual app launch (AutoRedTUI.run()) is left to a follow-up
        # task — for now ``--tui`` is accepted and the engagement runs
        # in auto-approve headless mode with the EventBus active.
        console.print(
            "[bold yellow]TUI mode requested — running with EventBus wired.[/]"
        )
        console.print(
            "[dim](Full Textual UI launch ships in a follow-up — "
            "engagement runs headless with auto-approve HitL.)[/]"
        )

    roe_config = load_roe(roe)
    engagement_id = generate_engagement_id(target, name)

    console.print(f"[bold green]Starting engagement (headless):[/] {engagement_id}")
    console.print(f"  Target: {target}")
    console.print(f"  RoE: {roe}")
    console.print(f"  Operator: {roe_config.operator}")

    # Register RoE for the guard before any tool call can fire.
    register_roe(engagement_id, roe_config)

    # Materialise the engagement folder so subsequent writes (state.json,
    # state.db, raw tool output, evidence) have somewhere to land.
    init_engagement_folder(engagement_id, target, roe_config.operator)

    # Build the initial EngagementState.
    state = EngagementState(
        engagement_id=engagement_id,
        target_scope=[target],
        operator=roe_config.operator,
        rules_of_engagement=roe_config,
    )

    # Phase 3: every engagement gets an EventBus on its state so the
    # Exploit Agent's HitL gates can emit/await operator responses.
    # In sandbox (auto_approve) mode the gates don't block; in
    # interactive mode the TUI (when --tui is set) drains the queue.
    state.event_bus = EventBus()

    log.info("engagement_start", engagement_id=engagement_id, target=target)

    async def _run():
        # The checkpointer owns an open aiosqlite connection — we close it
        # in the ``finally`` below to avoid leaking file descriptors.
        checkpointer = await make_checkpointer(engagement_id)
        graph = build_phase4_graph(checkpointer)
        config = {"configurable": {"thread_id": engagement_id}}
        try:
            final_state = await graph.ainvoke(state, config=config)
            return final_state
        finally:
            # AsyncSqliteSaver stores the connection on ``.conn`` per the
            # sqlite_saver module docstring.
            conn = getattr(checkpointer, "conn", None)
            if conn is not None:
                await conn.close()

    try:
        final_state = asyncio.run(_run())
        # ``graph.ainvoke`` may return either a dict (LangGraph's raw
        # state-dict form) or a hydrated ``EngagementState``; normalise.
        if isinstance(final_state, dict):
            final_phase = final_state.get("phase", "unknown")
            hosts = final_state.get("hosts", [])
            final_state_obj = EngagementState.model_validate(final_state)
        else:
            final_phase = final_state.phase
            hosts = final_state.hosts
            final_state_obj = final_state

        save_state_to_disk(engagement_id, final_state_obj)
        console.print(f"[bold green]Engagement complete:[/] {engagement_id}")
        console.print(f"  Phase: {final_phase}")
        console.print(f"  Hosts found: {len(hosts)}")
    except KeyboardInterrupt:
        console.print(
            f"\n[yellow]Interrupted. State saved. Resume with:[/] "
            f"autored resume {engagement_id}"
        )
        save_state_to_disk(engagement_id, state)
    except Exception as e:  # noqa: BLE001 — top-level CLI error boundary
        console.print(f"[bold red]Error:[/] {e}")
        log.error("engagement_failed", engagement_id=engagement_id, error=str(e))
        # Best-effort save so the operator can resume after a crash.
        try:
            save_state_to_disk(engagement_id, state)
        except Exception:  # noqa: BLE001
            pass
        raise typer.Exit(code=1)


# --------------------------------------------------------------------------- #
# resume
# --------------------------------------------------------------------------- #
@app.command()
def resume(engagement_id: str):
    """Resume an interrupted engagement.

    Phase 1 stub: loads the saved state from disk and prints the last
    phase + iteration count. Full resume logic (re-build the graph and
    re-invoke it with the existing state) ships in a later iteration.
    """
    from autored.persistence.filesystem import load_state_from_disk

    console.print(f"[bold yellow]Resuming engagement:[/] {engagement_id}")
    state = load_state_from_disk(engagement_id)
    if state is None:
        console.print(f"[bold red]Error:[/] No state found for {engagement_id}")
        raise typer.Exit(code=1)
    console.print(f"  Last phase: {state.phase}")
    console.print(f"  Iteration: {state.iteration_count}")
    # TODO: implement resume logic — re-build graph, invoke with existing state.


# --------------------------------------------------------------------------- #
# engagements
# --------------------------------------------------------------------------- #
@app.command()
def engagements():
    """List all engagements."""
    from autored.persistence.filesystem import list_engagements

    table = Table(title="Engagements")
    table.add_column("ID", style="cyan")
    table.add_column("Target")
    table.add_column("Operator")
    table.add_column("Started")
    for eng in list_engagements():
        table.add_row(eng["id"], eng["target"], eng["operator"], eng["started_at"])
    console.print(table)


# --------------------------------------------------------------------------- #
# version
# --------------------------------------------------------------------------- #
@app.command()
def version():
    """Show version."""
    console.print("AutoRed v0.1.0 (Phase 1)")


# --------------------------------------------------------------------------- #
# roe-wizard (stub — full wizard ships in Phase 6)
# --------------------------------------------------------------------------- #
@app.command()
def roe_wizard():
    """Interactive RoE file generator (stub — full wizard ships in Phase 6)."""
    console.print("[yellow]RoE Wizard (stub)[/]")
    console.print("For lab work, use the pre-built sandbox config:")
    console.print("  autored run --target X --roe roe-sandbox.yaml --no-tui")
    console.print("")
    console.print("Full interactive wizard ships in Phase 6 with RoEEditorScreen TUI.")
    console.print("For now, copy roe-sandbox.yaml and edit manually.")


if __name__ == "__main__":
    app()
