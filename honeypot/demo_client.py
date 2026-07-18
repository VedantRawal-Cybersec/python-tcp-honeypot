"""Local demonstration client for testing the honeypot safely."""
from __future__ import annotations

import argparse
import socket


def main() -> None:
    parser = argparse.ArgumentParser(description="Send a harmless local test payload")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--message", default="demo-client-probe")
    args = parser.parse_args()

    with socket.create_connection((args.host, args.port), timeout=5) as client:
        print(client.recv(512).decode("utf-8", errors="replace").strip())
        client.sendall(args.message.encode("utf-8"))
        print(client.recv(512).decode("utf-8", errors="replace").strip())


if __name__ == "__main__":
    main()
