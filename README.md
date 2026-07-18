# Python TCP Honeypot

A safe, low-interaction honeypot that imitates an SSH-style TCP service and records connection activity in structured JSON-lines logs. It is intended for an isolated lab, localhost demonstrations, and defensive cybersecurity learning.

> **Safety boundary:** The default configuration binds only to `127.0.0.1`. The application does not execute received input, provide a shell, collect passwords, download files, or modify production data.

## Project objectives

- Understand how low-interaction honeypots observe unsolicited connections.
- Record timestamps, source metadata, bounded payload previews, and connection outcomes.
- Analyze events and produce a concise summary for incident-review exercises.
- Demonstrate safe concurrency, configuration management, logging, and tests.

## Technology

- Python 3.10+
- Standard-library sockets and threading
- JSON-lines event storage
- pytest

## Repository structure

```text
python_honeypot_project/
├── config/settings.json
├── honeypot/
│   ├── server.py
│   ├── logger.py
│   ├── analyze.py
│   └── demo_client.py
├── logs/
├── tests/
├── requirements.txt
└── README.md
```

## Installation

```bash
python -m venv .venv
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Install the test dependency:

```bash
pip install -r requirements.txt
```

## Safe local demonstration

Start the honeypot from the project root:

```bash
python -m honeypot.server
```

In another terminal, run the included harmless client:

```bash
python -m honeypot.demo_client
```

Stop the server with `Ctrl+C`.

Review the log:

```bash
python -m honeypot.analyze
```

The analyzer writes `logs/summary.json` and prints statistics such as event counts, source counts, and total received bytes.

## Configuration

`config/settings.json` contains:

- `host`: bind address; defaults to localhost.
- `port`: listening port; defaults to 2222.
- `banner`: harmless SSH-like identification string.
- `connection_timeout_seconds`: idle-client timeout.
- `max_payload_bytes`: strict upper bound on received data.
- `log_file`: JSON-lines destination.

Keep the default localhost binding for demonstrations. Any broader deployment must be explicitly authorized, isolated, monitored, and compliant with applicable policy and law.

## Event format

Example:

```json
{
  "timestamp": "2026-07-18T10:00:00+00:00",
  "event_type": "payload_received",
  "source_ip": "127.0.0.1",
  "source_port": 50000,
  "byte_count": 17,
  "payload_preview": "demo-client-probe",
  "payload_hex": "64656d6f2d636c69656e742d70726f6265"
}
```

## Run tests

```bash
pytest -q
```

## Security design decisions

- Localhost-only default exposure.
- Input is logged as text/hex and never executed.
- Payload size is bounded to prevent unrestrained collection.
- Connections time out automatically.
- Logs are append-only from the application's perspective.
- The server provides no authentication workflow or interactive shell.

## Limitations and future work

- This is a low-interaction educational sensor, not a production deception platform.
- IP addresses observed through NAT or proxies may not identify an original source.
- Future work could add privacy-aware dashboards, rate limiting, signed log rotation, SIEM export, and Docker-based isolation.

## Suggested LinkedIn/GitHub description

> Built a safe Python TCP honeypot for defensive cybersecurity learning. The project uses localhost-only defaults, bounded input collection, structured JSON-lines logging, event analysis, graceful shutdown, and automated tests. Client input is never executed.

## Author

Vedant Rawal — Cybersecurity and AI learner
