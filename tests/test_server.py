import socket
from pathlib import Path

from honeypot.server import HoneypotServer


def test_handle_client_records_payload(tmp_path: Path) -> None:
    settings = {
        "host": "127.0.0.1",
        "port": 0,
        "banner": "TEST-BANNER",
        "connection_timeout_seconds": 1,
        "max_payload_bytes": 128,
        "log_file": str(tmp_path / "events.jsonl"),
    }
    server = HoneypotServer(settings)
    server_side, client_side = socket.socketpair()
    client_side.sendall(b"harmless-test")
    server.handle_client(server_side, ("127.0.0.1", 50000))
    response = client_side.recv(1024)
    client_side.close()

    log_text = (tmp_path / "events.jsonl").read_text(encoding="utf-8")
    assert b"TEST-BANNER" in response
    assert "payload_received" in log_text
    assert "harmless-test" in log_text
