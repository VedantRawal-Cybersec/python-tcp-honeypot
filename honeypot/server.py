"""A low-interaction TCP honeypot for authorized lab environments.

The service records connection metadata and a small, bounded payload. It never
executes client input, authenticates users, captures malware, or changes system
state beyond appending to its own log file.
"""
from __future__ import annotations

import argparse
import json
import signal
import socket
import threading
from pathlib import Path
from typing import Any

from honeypot.logger import EventLogger


class HoneypotServer:
    def __init__(self, settings: dict[str, Any]) -> None:
        self.host = str(settings.get("host", "127.0.0.1"))
        self.port = int(settings.get("port", 2222))
        self.banner = str(settings.get("banner", "SSH-2.0-OpenSSH_8.9"))
        self.timeout = float(settings.get("connection_timeout_seconds", 8))
        self.max_payload_bytes = int(settings.get("max_payload_bytes", 2048))
        self.logger = EventLogger(Path(settings.get("log_file", "logs/events.jsonl")))
        self._stop_event = threading.Event()
        self._socket: socket.socket | None = None

    def stop(self) -> None:
        self._stop_event.set()
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass

    def handle_client(self, client: socket.socket, address: tuple[str, int]) -> None:
        source_ip, source_port = address
        self.logger.write("connection_opened", source_ip=source_ip, source_port=source_port)
        client.settimeout(self.timeout)
        try:
            client.sendall((self.banner + "\r\n").encode("utf-8"))
            payload = client.recv(self.max_payload_bytes)
            if payload:
                self.logger.write(
                    "payload_received",
                    source_ip=source_ip,
                    source_port=source_port,
                    byte_count=len(payload),
                    payload_preview=payload[:256].decode("utf-8", errors="replace"),
                    payload_hex=payload[:128].hex(),
                )
            client.sendall(b"Protocol mismatch. Connection closed.\r\n")
        except socket.timeout:
            self.logger.write("connection_timeout", source_ip=source_ip, source_port=source_port)
        except OSError as exc:
            self.logger.write(
                "connection_error",
                source_ip=source_ip,
                source_port=source_port,
                error=str(exc),
            )
        finally:
            try:
                client.close()
            except OSError:
                pass
            self.logger.write("connection_closed", source_ip=source_ip, source_port=source_port)

    def serve_forever(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket = server
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(30)
        server.settimeout(1.0)
        self.logger.write("server_started", host=self.host, port=self.port)
        print(f"Honeypot listening on {self.host}:{self.port}")

        try:
            while not self._stop_event.is_set():
                try:
                    client, address = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self._stop_event.is_set():
                        break
                    raise
                thread = threading.Thread(
                    target=self.handle_client, args=(client, address), daemon=True
                )
                thread.start()
        finally:
            self.logger.write("server_stopped", host=self.host, port=self.port)
            try:
                server.close()
            except OSError:
                pass


def load_settings(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the educational TCP honeypot")
    parser.add_argument("--config", type=Path, default=Path("config/settings.json"))
    parser.add_argument("--host", help="Override configured bind host")
    parser.add_argument("--port", type=int, help="Override configured port")
    args = parser.parse_args()

    settings = load_settings(args.config)
    if args.host:
        settings["host"] = args.host
    if args.port:
        settings["port"] = args.port

    server = HoneypotServer(settings)
    signal.signal(signal.SIGINT, lambda *_: server.stop())
    signal.signal(signal.SIGTERM, lambda *_: server.stop())
    server.serve_forever()


if __name__ == "__main__":
    main()
