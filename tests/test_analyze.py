from honeypot.analyze import build_summary


def test_summary_counts_events() -> None:
    events = [
        {"event_type": "connection_opened", "source_ip": "127.0.0.1"},
        {
            "event_type": "payload_received",
            "source_ip": "127.0.0.1",
            "byte_count": 12,
        },
        {"event_type": "connection_closed", "source_ip": "127.0.0.1"},
    ]
    summary = build_summary(events)
    assert summary["total_events"] == 3
    assert summary["unique_source_ips"] == 1
    assert summary["payload_events"] == 1
    assert summary["total_payload_bytes"] == 12
