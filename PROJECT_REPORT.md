# Project Report: Python TCP Honeypot

## Problem statement
Defenders benefit from controlled deception systems that record unsolicited connection behavior without exposing a real service. This project demonstrates the core design of a low-interaction honeypot.

## Approach
The honeypot exposes an SSH-like banner, receives only a strictly bounded payload, records structured events, and closes the connection. It does not execute input or provide a shell. The default bind address is localhost to make the demonstration safe and repeatable.

## Validation
Automated tests verify JSON-lines logging, event aggregation, connection handling, banner delivery, and payload recording. A harmless demo client is included for local testing.

## Result
The application records connection lifecycle events and produces a summary containing event counts, unique sources, and payload statistics. The implementation is intentionally small enough to explain during an internship evaluation.

## Learning outcomes
- TCP socket programming
- Defensive deception concepts
- Thread-safe structured logging
- Safe input handling and strict collection limits
- Event analysis and security design documentation
