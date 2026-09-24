from __future__ import annotations

import json
from pathlib import Path

from autored.logging import setup_logging, get_logger


def test_logger_emits_json(tmp_path: Path):
    log_dir = tmp_path / "logs"
    setup_logging(str(log_dir))
    log = get_logger("test")
    log.info("hello", key="value", number=42)
    # Find the log file
    log_files = list(log_dir.glob("*.jsonl"))
    assert len(log_files) == 1
    line = log_files[0].read_text().strip().splitlines()[-1]
    parsed = json.loads(line)
    assert parsed["event"] == "hello"
    assert parsed["key"] == "value"
    assert parsed["number"] == 42
    assert parsed["level"] == "info"


def test_setup_logging_is_idempotent(tmp_path: Path):
    log_dir = tmp_path / "logs"
    setup_logging(str(log_dir))
    setup_logging(str(log_dir))  # should not raise
    log = get_logger("test")
    log.info("second_call")
    log_files = list(log_dir.glob("*.jsonl"))
    assert len(log_files) == 1
