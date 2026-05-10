# NIDS - Network Intrusion Detection System

Production-ready full-stack NIDS with real-time packet capture, behavioral analysis, correlated threat detection, and SIEM-style dashboard UI.

## Tech stack

- Backend: Python + Flask + Flask-SocketIO + Scapy + SQLite
- Frontend: React + Recharts + react-window + socket.io-client

## Features implemented

- Scapy live capture in promiscuous mode, selectable interface, start/stop control
- Six-module backend pipeline:
  - `capture.py` (Module 1)
  - `extractor.py` (Module 2)
  - `analyser.py` (Module 3)
  - `correlator.py` (Module 4)
  - `alert_generator.py` (Module 5)
  - `logger.py` (Module 6)
- Sliding-window analysis with `deque`, configurable thresholds, hot-reload settings
- Threats: slow/rapid port scan, brute force, ping sweep, anomalous volume, composite
- Severity and risk scoring (LOW/MEDIUM/HIGH/CRITICAL) with attack spikes in graph
- SQLite persistence, log filtering endpoints, CSV/JSON/PCAP-style export during capture
- Full 5-panel dark-theme dashboard and settings modal

## Run instructions

> Scapy requires root/sudo for live packet capture.

Run backend:

```bash
sudo python backend/main.py
