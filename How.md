# NetAuditX ULTRA

AI-powered network intelligence & audit platform. FastAPI backend + vanilla
HTML/JS cyber-SOC dashboard. Lives at the **workspace root** (not inside
`artifacts/`) and runs as the `Start application` workflow on port **5000**.

## v2.0 — Network Intelligence Platform

Major upgrade from a basic SSH-only auditor to a full network intelligence
platform with discovery, predictive vulnerability scoring, drift detection,
live log streaming, and a network topology map.

### What's new
* **Subnet discovery** (`/api/discover`): ARP sweep via Scapy when raw sockets
  are available, otherwise async TCP-connect probes against the top ~50
  hot ports. Banner-grabs services, reverse-resolves hostnames, persists
  results to inventory. Sweeps a /24 within ~60s on commodity hardware.
* **Predictive port-vulnerability analyzer** (`backend/ai/vuln_kb.py`):
  ~40-port curated KB with weighted base risk + 14 banner-pattern CVE
  detectors (vsftpd backdoor, OpenSSH legacy, Apache/IIS EOL, etc.). Folded
  into the network risk score by `analyze()`.
* **Network drift detection** (`/api/drift`): every discovery + scan runs a
  snapshot diff and emits `new_device`, `gone_device`, `new_port`,
  `closed_port`, `service_changed` events. New-device events fire critical
  alerts.
* **Live log streaming** (`/api/logs/stream` SSE): every backend log line
  fans out to subscribed UI clients in real time via an in-process pub/sub
  bus + ring buffer.
* **Network topology map** page: hub-and-spoke SVG visualization coloured
  by status, with hover tooltips.
* **Cyber-SOC neon UI overhaul**: deep-navy void background, cyan/magenta
  accents, scanlines, glow effects — keeps the glassmorphism panels.
* **Idempotent demo seed** keyed by IP (no more duplicate inserts on
  restart).
* **Structured JSON error envelope** so the UI never sees an HTML
  traceback page.
* **Lightweight column migrations** in `init_db()` — adds the new
  `Device` columns to existing Postgres/SQLite databases without losing
  data.

## How to run

* The `Start application` workflow runs:
  `python -m uvicorn backend.api.main:app --host 0.0.0.0 --port 5000`
* Open `/` for the dashboard, `/docs` for OpenAPI, `/api/health` for liveness.
* Docker: `docker compose up --build`.

## Project structure

```
backend/
  api/
    main.py              FastAPI app (lifespan, CORS, demo seed, error envelope, mounts /api + frontend)
    schemas.py           Pydantic request/response models (incl. DiscoveryRequest/Response, DriftEventOut)
    routes/              devices, scan, insights, alerts, scheduler, dashboard, discover, drift, logs
  core/
    device_detection.py  Vendor heuristics + TTL cache
    ssh_engine.py        AsyncSSH-based concurrent scanner
    discovery.py         ARP (Scapy, optional) + async TCP-connect subnet sweep, banner grabbing, RDNS
    drift.py             Snapshot persistence + diff → DriftEvent rows
  ai/
    anomaly.py           Detects flapping, mass failure, repeated auth failure, uptime resets
    vuln_kb.py           Port → service/risk KB + banner-pattern CVE detectors + TOP_TCP_PORTS
    analyzer.py          Weighted risk scoring (reachability + anomalies + port vulns); optional OpenAI summary
  alerts/
    email_sender.py      aiosmtplib delivery
    webhook_sender.py    httpx JSON POST delivery
    manager.py           Severity routing + dedup window + alert audit log
  scheduler/
    scheduler.py         APScheduler (interval) integration
  db/
    models.py            SQLAlchemy 2.x ORM (Device, ScanResult, OpenPort, DriftEvent, Insight, Alert, …)
    database.py          Engine + sessionmaker + init_db() with lightweight ALTER-TABLE migrations
  utils/
    logger.py            Rotating file + stdout + log-bus handler
    log_bus.py           In-process pub/sub + ring buffer for SSE
    parsers.py           Vendor-specific output parsers
    validators.py        IP/hostname/port validation
  config.py              Pydantic Settings (env-driven)
frontend/
  app/
    index.html           Single-page shell (sidebar with 10 routes, topbar, #view)
    app.js               Hash router with per-page cleanup hooks + auto-refresh
  components/
    api.js               Fetch wrapper for /api/* (incl. discover, listDrift, streamLogs)
    ui.js                Toast, status badges, severity badges, formatters
  pages/
    dashboard.js         Stat tiles, vendor breakdown, recent results & insights
    discovery.js         CIDR sweep form + result table (per-host risk / open ports)
    network_map.js       Pure-SVG hub-and-spoke topology with tooltips
    devices.js           Inventory CRUD
    results.js           Filterable scan-result table + raw output viewer
    insights.js          Risk gauge, anomalies, recommendations, history sparkline
    drift.js             Drift-event timeline with kind/severity filters
    alerts.js            Alert history with severity filter
    schedules.js         APScheduler job CRUD
    logs.js              EventSource-driven SOC console (pause / clear / level filter)
  styles/main.css        Cyber-SOC neon theme (deep-navy + cyan/magenta + scanlines + glassmorphism)
data/                    SQLite DB (used when Postgres URL is not provided)
logs/                    Rotating netauditx.log
exports/                 Project archive
requirements.txt, Dockerfile, docker-compose.yml, README.md, .env.example
```

## Database

Uses the workspace-provided `DATABASE_URL` (PostgreSQL via `psycopg2-binary`)
when present; otherwise falls back to `sqlite:///data/netauditx.db`. Schema is
auto-created on boot via `Base.metadata.create_all`, and `init_db()` runs a
small idempotent ALTER-TABLE pass to add any missing columns introduced by a
new release.

## Demo data

`SEED_DEMO_DATA=true` (default) inserts any missing demo devices on boot
(keyed by IP — restarts no longer duplicate them). Triggering a scan
produces realistic offline results, fires alerts (with dedup), and
populates AI insights.

## Environment variables

See `.env.example`. None required to start; configure `SMTP_*`,
`ALERT_WEBHOOK_URL`, `OPENAI_API_KEY`, and `SSH_DEFAULT_*` for production.

## Dependencies

Python 3.11. Installed packages: `fastapi`, `uvicorn[standard]`, `asyncssh`,
`sqlalchemy`, `apscheduler`, `pydantic`, `pydantic-settings`,
`python-multipart`, `aiosmtplib`, `httpx`, `jinja2`, `python-dotenv`,
`psycopg2-binary`, `scapy`. Tracked in `requirements.txt`.

> **Scapy & raw sockets:** Scapy's ARP sweep needs `CAP_NET_RAW`, which is
> typically not granted in containerized environments (including Replit's
> sandbox). The discovery engine detects this transparently and falls back
> to the async TCP-connect sweep, so the platform works everywhere — ARP
> simply enriches results with MAC addresses when it's available.

## Coexistence with monorepo artifacts

The two pre-existing artifacts (`artifacts/api-server`,
`artifacts/mockup-sandbox`) are untouched and continue to run on their own
ports. NetAuditX is intentionally a standalone Python service at the
workspace root and is not registered as an artifact.
