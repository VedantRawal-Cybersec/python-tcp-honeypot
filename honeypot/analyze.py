"""Summarize honeypot JSON-lines events."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


def load_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON on line {line_number}: {exc}") from exc
    return events


def build_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    event_types = Counter(str(item.get("event_type", "unknown")) for item in events)
    source_ips = Counter(
        str(item["source_ip"]) for item in events if item.get("source_ip") is not None
    )
    payload_events = [item for item in events if item.get("event_type") == "payload_received"]
    total_payload_bytes = sum(int(item.get("byte_count", 0)) for item in payload_events)
    return {
        "total_events": len(events),
        "event_types": dict(event_types.most_common()),
        "unique_source_ips": len(source_ips),
        "top_source_ips": source_ips.most_common(10),
        "payload_events": len(payload_events),
        "total_payload_bytes": total_payload_bytes,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze honeypot events")
    parser.add_argument("--log", type=Path, default=Path("logs/events.jsonl"))
    parser.add_argument("--output", type=Path, default=Path("logs/summary.json"))
    args = parser.parse_args()

    summary = build_summary(load_events(args.log))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
