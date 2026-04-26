# NetAuditX ULTRA

**AI Network Intelligence & Monitoring Platform**

A lightweight, enterprise-grade network monitoring + AI analysis system. NetAuditX
audits network devices over SSH, stores structured results in a database, runs an
AI analyzer to score risk and detect anomalies, fires alerts via email/webhook,
and schedules continuous scans — all behind a real-time glassmorphism dashboard.

---

## Highlights

* **Async SSH scanning** with [`asyncssh`](https://asyncssh.readthedocs.io/) — high concurrency, vendor-aware probes, retries, timeouts, sanitized output.
* **Auto-detection** of device vendor (Cisco, Juniper, Arista, MikroTik, Huawei, Fortinet, Linux, VyOS, Palo Alto) with TTL caching and graceful fallbacks.
* **AI analysis engine** — rule-based engine (always on) computes a 0–100 risk score, generates a structured JSON insight (summary + anomalies + recommendations) and detects flapping devices, mass failures, repeated auth failures, and uptime resets. Optional OpenAI refinement of the summary text.
* **Alerts** — SMTP email + JSON webhook delivery with severity levels (info/warning/critical), deduplication via fingerprint + sliding window, and full audit log.
* **Scheduler** — APScheduler runs configurable periodic scans entirely in-process.
* **Database** — SQLAlchemy 2.x ORM, SQLite by default, drop-in PostgreSQL via `DATABASE_URL`.
* **FastAPI** — clean, modular routes with Pydantic validation, full OpenAPI docs at `/docs`.
* **Glassmorphism dashboard** — dark theme, responsive, auto-refreshing, 5+ pages (Dashboard, Devices, Scan Results, AI Insights, Alerts, Schedules).
* **Production-ready DevOps** — `Dockerfile`, `docker-compose.yml`, healthcheck, `.env.example`, rotating file logs.

---

## Project layout

```
NetAuditX/
├── backend/
│   ├── api/                FastAPI application + routes + schemas
│   ├── core/               Async SSH scanning engine + device detection
│   ├── ai/                 Rule-based analyzer + anomaly detection
│   ├── alerts/             Email / webhook senders + alert manager
│   ├── scheduler/          APScheduler integration
│   ├── db/                 SQLAlchemy models + connection layer
│   ├── utils/              Logging, parsing, validation helpers
│   └── config.py           Strongly-typed settings (env-driven)
├── frontend/
│   ├── app/                Single-page dashboard entry (HTML)
│   ├── components/         Shared JS modules (api client, UI helpers)
│   ├── pages/              One module per page
│   └── styles/             Global CSS (glass theme, dark)
├── data/                   SQLite DB lives here
├── logs/                   Rotating application log
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## Quick start (local)

### 1. Install Python deps

```bash
pip install -r requirements.txt
```

Python 3.11+ is required.

### 2. (Optional) Configure environment

```bash
cp .env.example .env
# edit .env to set SMTP / webhook / OpenAI / SSH defaults
```

NetAuditX runs out of the box with no `.env` file — all settings have safe defaults.

### 3. Run the server

```bash
python -m uvicorn backend.api.main:app --host 0.0.0.0 --port 5000
```

Then open **http://localhost:5000** in your browser.

* Dashboard:  `http://localhost:5000/`
* API docs:    `http://localhost:5000/docs`
* Health:      `http://localhost:5000/api/health`

The first launch creates `data/netauditx.db`, seeds 4 demo devices, and starts
the scheduler. Click **⚡ Scan Now** in the top bar (or `POST /api/scan`) to run
an audit pass — the dashboard will populate with results, AI insights, and any
fired alerts.

---

## Run with Docker

```bash
docker compose up --build
```

The container exposes port 5000, persists `./data` (SQLite) and `./logs`. Configure
SMTP / webhook / OpenAI by uncommenting the appropriate environment variables in
`docker-compose.yml`.

---

## API examples

All endpoints live under `/api`. Full interactive docs at `/docs`.

### Trigger a scan

```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"targets": ["10.10.0.1"], "username": "admin", "password": "s3cret"}'
```

Example response (truncated):

```json
{
  "scanned": 1,
  "success": 0,
  "failed": 1,
  "results": [
    {
      "ip": "10.10.0.1",
      "status": "offline",
      "vendor": "cisco",
      "uptime_seconds": null,
      "uptime_human": "unknown",
      "raw_output": "",
      "error": "Connection timed out",
      "duration_ms": 8021,
      "name": "Core Router (demo)",
      "commands_run": []
    }
  ],
  "insight": {
    "summary": "Network status: AT RISK (risk score 75/100). 0/1 devices reachable; 1 failed/offline. Vendors observed: unknown. Detected 1 anomaly(ies) — 1 critical, 0 warning.",
    "risk_score": 75,
    "anomalies": [
      {
        "type": "mass_failure",
        "severity": "critical",
        "target": "network",
        "message": "1 of 1 devices failed in this scan — possible network outage."
      }
    ],
    "recommendations": [
      "Investigate 1 unreachable device(s): 10.10.0.1.",
      "Treat as a possible network-wide outage: validate management VLAN, jump host and DNS resolution before further scans."
    ],
    "devices_total": 1,
    "devices_failed": 1,
    "source": "rule-based"
  },
  "alerts_emitted": 3
}
```

### List devices / results / insights / alerts

```bash
curl http://localhost:5000/api/devices
curl http://localhost:5000/api/results?limit=20
curl http://localhost:5000/api/insights/latest
curl http://localhost:5000/api/alerts?severity=critical
```

### Schedule a recurring scan

```bash
curl -X POST http://localhost:5000/api/scan/schedule \
  -H "Content-Type: application/json" \
  -d '{"name": "hourly-edge-audit", "interval_minutes": 60, "targets": []}'
```

Empty `targets` means "scan every enabled device". Re-using the same `name`
updates the existing schedule in place.

---

## AI insight payload shape

The analyzer always returns a structured JSON object:

```json
{
  "summary": "Network status: HEALTHY (risk score 8/100). 24/24 devices reachable...",
  "risk_score": 8,
  "anomalies": [
    { "type": "uptime_reset", "severity": "warning", "target": "10.0.0.5",
      "message": "10.0.0.5 appears to have rebooted (uptime dropped from 1209600s to 90s)." }
  ],
  "recommendations": [
    "All monitored devices are healthy. Continue normal monitoring."
  ]
}
```

If `OPENAI_API_KEY` is set, the engine attempts to refine the `summary` text
using the OpenAI Chat Completions API; failures fall back silently to the
rule-based summary.

---

## Configuration reference

See [`.env.example`](./.env.example) for every supported variable. Highlights:

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `5000` | Bind port |
| `DATABASE_URL` | `sqlite:///data/netauditx.db` | SQLAlchemy URL (Postgres supported) |
| `SSH_DEFAULT_USERNAME` / `_PASSWORD` | `admin` / "" | Used if a device row has no creds |
| `SSH_TIMEOUT` | `8` | Seconds per device |
| `SSH_MAX_CONCURRENCY` | `32` | Concurrent SSH connections |
| `SCHEDULER_ENABLED` | `true` | Toggle APScheduler entirely |
| `ALERT_FAILURE_THRESHOLD` | `3` | Devices failing in one scan → critical alert |
| `ALERT_RISK_SCORE_THRESHOLD` | `70` | Risk score → critical alert |
| `ALERT_DEDUP_WINDOW_MINUTES` | `30` | Dedup fingerprint window |
| `SMTP_HOST` / `_PORT` / `_USERNAME` / `_PASSWORD` / `_USE_TLS` | — | Email delivery |
| `ALERT_EMAIL_FROM` / `_TO` | — | Sender / recipient(s) |
| `ALERT_WEBHOOK_URL` | — | JSON POST destination |
| `OPENAI_API_KEY` / `OPENAI_MODEL` | — / `gpt-4o-mini` | Optional AI refinement |
| `SEED_DEMO_DATA` | `true` | Set false in production |

---

## Logs

Application logs are streamed to stdout **and** rotated into `logs/netauditx.log`
(5 × 2 MB).

---

## License

MIT.
