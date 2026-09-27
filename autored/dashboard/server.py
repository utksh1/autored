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
