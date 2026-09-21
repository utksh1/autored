# tests/unit/test_logging.py
import json
from autored.logging import setup_logging, get_logger

def test_logger_emits_json(tmp_path):
    setup_logging(log_dir=str(tmp_path))
    log = get_logger("test")
    log.info("test_event", key="value")
    # Find today's log file
    log_files = list(tmp_path.glob("*.jsonl"))
    assert len(log_files) == 1
    line = log_files[0].read_text().strip()
    entry = json.loads(line)
    assert entry["event"] == "test_event"
    assert entry["key"] == "value"
    assert "timestamp" in entry
    assert entry["level"] == "info"
