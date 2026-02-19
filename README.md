
# NOTE THIS IS FOR DEMONSTRATION AND PROJECT PURPOSES. Future changes may be implemented if I decide to go further with it

# SIEM Log Dashboard

Real-time Security Information and Event Management dashboard built with Python and Flask. Ingests simulated syslog, firewall, and authentication logs, normalizes them into a structured database, runs correlation rules to detect attack patterns, and displays everything through a live-updating web interface with filtering and time range selection.

## Features

- **Log Ingestion Pipeline** — Generates realistic syslog/firewall/auth events, parses and normalizes them, stores in SQLite with indexed lookups
- **Threat Correlation Engine** — Detects brute force attempts, port scans, and DDoS patterns using configurable thresholds and time windows
- **Multi-Stage Attack Simulation** — A realistic 6-phase intrusion scenario (recon → brute force → access → priv esc → persistence → exfiltration) plays out gradually alongside normal traffic
- **Real-Time Dashboard** — WebSocket-driven updates via Flask-SocketIO, no page refresh needed
- **Time Range Picker** — Filter all dashboard data by preset ranges (15m, 1h, 6h, 24h) or custom datetime windows
- **Event Filtering** — Filter the event feed by severity, event type, and source IP
- **Geographic Threat Map** — Leaflet.js map plotting event sources by country/city with threat-level coloring
- **MITRE ATT&CK Mapping** — Events and alerts tagged with MITRE tactics and technique IDs (T1110, T1046, T1498, T1071, T1041, T1068, T1098)
- **Threat Intelligence Feed** — Simulated TI watchlist that flags known-bad IPs and tracks hit counts over time
- **Alert Management** — Analysts can acknowledge alerts and add investigation notes
- **Token Authentication** — All API endpoints require a valid token via header or query param
- **HTML Sanitization** — All user-facing string output is escaped server-side (markupsafe) and client-side to prevent XSS
- **Structured Data Models** — Events and alerts use Python dataclasses instead of raw tuples
- **Test Suite** — Unit tests covering correlation rules, threshold logic, database operations, model validation, and edge cases

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌────────────────┐
│ Log Generator│────▸│  Normalizer  │────▸│   SQLite DB    │
│  + Attack    │     │  (dataclass) │     │  (WAL mode)    │
│  Scenario    │     └──────┬───────┘     └───────┬────────┘
└──────────────┘            │                     │
                     ┌──────▼───────┐      ┌──────▼────────┐
                     │ Correlation  │      │  Flask API    │
                     │   Engine     │      │  + SocketIO   │
                     │  (rules +   │      │  + Token Auth │
                     │   MITRE)    │      └──────┬────────┘
                     └──────────────┘             │
                                           ┌──────▼────────┐
                                           │   Dashboard   │
                                           │  (Chart.js /  │
                                           │   Leaflet)    │
                                           └───────────────┘
```

## Setup

```bash
cd siem-dashboard
pip install -r requirements.txt
python app.py
```

Dashboard will be live at **http://127.0.0.1:5000**

The API token is printed to the console on startup. It defaults to `siem-ops-7f3a9c2e` and can be overridden with the `SIEM_API_TOKEN` environment variable.

## Running Tests

```bash
cd siem-dashboard
python -m pytest tests/ -v
```

The test suite covers:
- Brute force detection (above and below threshold)
- Port scan detection (above and below threshold)
- DDoS detection (volume-based)
- IP deduplication in correlation
- Threat intel flagging and hit tracking
- MITRE ATT&CK mapping on alerts
- Database CRUD (insert, query, filter, acknowledge, notes)
- Event model validation (tuple conversion, field defaults, severity bounds)
- Log generator output (batch size, dataclass type, severity validity)

## API Authentication

All endpoints under `/api/*` require a token. Pass it as:

- Header: `X-API-Token: siem-ops-7f3a9c2e`
- Query param: `?token=siem-ops-7f3a9c2e`

The dashboard handles this automatically. Direct API usage example:

```bash
curl -H "X-API-Token: siem-ops-7f3a9c2e" http://127.0.0.1:5000/api/stats
curl "http://127.0.0.1:5000/api/events?token=siem-ops-7f3a9c2e&severity=critical"
curl "http://127.0.0.1:5000/api/events?token=siem-ops-7f3a9c2e&since=1h"
```

## Time Range Filtering

Most API endpoints accept `since` and `until` parameters:

- Unix timestamp: `?since=1700000000`
- Relative: `?since=1h`, `?since=30m`, `?since=2d`

## Configuration

All thresholds are in `config.py`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `GENERATOR_INTERVAL` | 3s | Seconds between log batches |
| `LOG_BATCH_SIZE` | 20 | Events per batch |
| `BRUTE_FORCE_THRESHOLD` | 5 | Failed logins to trigger alert |
| `BRUTE_FORCE_WINDOW` | 300s | Rolling window for brute force |
| `PORT_SCAN_THRESHOLD` | 8 | Distinct ports to trigger alert |
| `DDOS_THRESHOLD` | 50 | Events/minute for DDoS alert |

## Attack Scenario

On startup, a multi-stage attack plays out automatically over ~2 minutes:

1. **Reconnaissance** (ticks 0-10) — Port scanning from a known-bad Russian IP
2. **Brute Force** (ticks 10-25) — Rapid SSH login attempts against common accounts
3. **Initial Access** (ticks 25-28) — Successful login after credential guessing
4. **Privilege Escalation** (ticks 28-32) — Unauthorized sudo to root
5. **Persistence** (ticks 32-38) — Backdoor SSH config, new user account, cron job
6. **Exfiltration** (ticks 38-45) — Large data transfers out to attacker IP

This gives the dashboard realistic data to correlate and display across all panels.

## Project Structure

```
siem-dashboard/
├── app.py                  # Flask app, routes, auth, WebSocket, ingestion loop
├── config.py               # Thresholds, MITRE mappings, threat intel list
├── models.py               # Event and Alert dataclasses
├── database.py             # SQLite schema, queries, filtering
├── log_generator.py        # Simulated log generation with geo profiles
├── correlation.py          # Brute force / port scan / DDoS detection
├── attack_scenario.py      # Multi-stage intrusion simulation
├── requirements.txt
├── templates/
│   └── dashboard.html      # Dashboard with filter bar and time picker
├── static/
│   ├── css/dashboard.css
│   └── js/dashboard.js     # Charts, WebSocket, safe rendering
└── tests/
    ├── __init__.py
    └── test_correlation.py # 20 unit tests
```

# note: AI help with organization and clarity for speeding some things in README up.

## Tech Stack

- **Backend:** Python 3, Flask, Flask-SocketIO
- **Database:** SQLite (WAL mode, indexed)
- **Frontend:** Vanilla JavaScript, Chart.js, Leaflet.js
- **Real-time:** WebSocket via Socket.IO
- **Security:** Token auth, markupsafe HTML escaping
- **Testing:** unittest / pytest

## Limitations & Future Work

This project demonstrates the core architecture of a SIEM platform, but there are areas where a production system would go further:

# SOME LIMITS, AS IT IS FOR DEMONSTRATION AND PROJECT PURPOSES AGAIN
