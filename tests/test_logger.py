import json
from pathlib import Path

from honeypot.logger import EventLogger


def test_event_logger_writes_json_line(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    logger = EventLogger(path)
    logger.write("test_event", source_ip="127.0.0.1", value=3)
    record = json.loads(path.read_text(encoding="utf-8").strip())
    assert record["event_type"] == "test_event"
    assert record["source_ip"] == "127.0.0.1"
