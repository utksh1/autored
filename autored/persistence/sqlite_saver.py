"""LangGraph SQLite checkpointer factory.

Each engagement gets its own SQLite DB at
``engagements/<engagement_id>/state.db``. LangGraph stores every
checkpoint (state snapshot + writes) in there, so an engagement that
crashes mid-iteration can be resumed by pointing the graph at the same
``thread_id`` and DB.

Implementation note
-------------------
``AsyncSqliteSaver.from_conn_string`` is decorated with
``@asynccontextmanager`` — it yields a saver from inside an
``async with aiosqlite.connect(...)`` block, so it cannot be returned
directly from an ``async def`` that wants to hand back a live saver.
We instead open the connection eagerly with ``aiosqlite.connect`` and
construct the saver manually (the documented "raw usage" pattern from
``AsyncSqliteSaver``'s docstring). Callers that want clean teardown can
``await saver.conn.close()`` after the graph finishes.
"""

from pathlib import Path

import aiosqlite
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

from autored.logging import get_logger
from autored.persistence.filesystem import ENGAGEMENTS_DIR

log = get_logger("persistence.sqlite_saver")


async def make_checkpointer(engagement_id: str) -> AsyncSqliteSaver:
    """Create a SQLite checkpointer for an engagement.

    The DB lives at ``engagements/<id>/state.db`` and stores LangGraph
    checkpoints for resume-after-crash capability.

    The connection is opened eagerly so the DB file exists on disk by the
    time this returns. The caller owns the connection's lifetime — for
    long-running CLI sessions, close it via ``await saver.conn.close()``
    before exiting.
    """
    folder = ENGAGEMENTS_DIR / engagement_id
    folder.mkdir(parents=True, exist_ok=True)
    db_path = folder / "state.db"
    log.info("checkpointer_init", engagement_id=engagement_id, db_path=str(db_path))
    # ``AsyncSqliteSaver.from_conn_string`` is an async context manager
    # rather than a direct constructor; open the connection ourselves so
    # we can hand back a live saver (see module docstring).
    conn = await aiosqlite.connect(str(db_path))
    return AsyncSqliteSaver(conn)
