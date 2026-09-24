"""AutoRed structlog JSON logging setup.

Logs are written to <log_dir>/<YYYY-MM-DD>.jsonl, one JSON object per line.
Logs also go to stderr for live visibility during TUI runs.
"""
from __future__ import annotations

import logging
import sys
from datetime import datetime
from pathlib import Path

import structlog

_SETUP_DONE = False
_CONFIGURED_LOG_DIR: str | None = None
_OUR_HANDLERS: list[logging.Handler] = []


def setup_logging(log_dir: str = "logs") -> None:
    """Configure structlog + a FileHandler writing to <log_dir>/<date>.jsonl.

    Idempotent: safe to call multiple times. Calls with the same ``log_dir``
    as the currently-configured target are no-ops. Calls with a different
    ``log_dir`` reconfigure handlers — this keeps per-test ``tmp_path``
    isolation working without sacrificing idempotency for repeated calls
    against the same directory (as exercised by the idempotency test).
    """
    global _SETUP_DONE, _CONFIGURED_LOG_DIR, _OUR_HANDLERS
    if _SETUP_DONE and _CONFIGURED_LOG_DIR == log_dir:
        return

    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)
    log_file = log_path / f"{datetime.utcnow().strftime('%Y-%m-%d')}.jsonl"

    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    root = logging.getLogger()
    # Detach handlers we previously attached so a reconfigure for a new
    # log_dir does not leak file descriptors or duplicate stderr output.
    for handler in _OUR_HANDLERS:
        root.removeHandler(handler)
        handler.close()
    _OUR_HANDLERS = []

    file_handler = logging.FileHandler(str(log_file), encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(message)s"))
    root.addHandler(file_handler)
    _OUR_HANDLERS.append(file_handler)

    # Mirror to stderr for live visibility during TUI runs (spec §3.2 audit
    # log lives on disk; the stderr stream is for the operator at the TUI).
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(logging.Formatter("%(message)s"))
    root.addHandler(stderr_handler)
    _OUR_HANDLERS.append(stderr_handler)

    root.setLevel(logging.INFO)

    _SETUP_DONE = True
    _CONFIGURED_LOG_DIR = log_dir


def get_logger(name: str) -> structlog.BoundLogger:
    """Get a structlog logger by name. Calls setup_logging() if not yet done."""
    if not _SETUP_DONE:
        setup_logging()
    return structlog.get_logger(name)
