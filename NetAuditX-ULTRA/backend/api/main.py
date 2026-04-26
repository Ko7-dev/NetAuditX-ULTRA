"""FastAPI application entry point."""

from __future__ import annotations

import traceback
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend.api.routes import (
    alerts,
    dashboard,
    devices,
    discover,
    drift,
    insights,
    logs,
    scan,
    scheduler,
)
from backend.config import FRONTEND_DIR, get_settings
from backend.db.database import init_db, session_scope
from backend.db.models import Device
from backend.scheduler.scheduler import shutdown_scheduler, start_scheduler
from backend.utils.logger import configure_logging, get_logger

configure_logging()
log = get_logger("netauditx.app")
settings = get_settings()


_DEMO_DEVICES = [
    {
        "name": "Core Router (demo)",
        "ip": "10.10.0.1",
        "port": 22,
        "username": "netaudit",
        "vendor_hint": "cisco",
        "tags": "core,router,demo",
    },
    {
        "name": "Access Switch A (demo)",
        "ip": "10.10.1.10",
        "port": 22,
        "username": "netaudit",
        "vendor_hint": "cisco",
        "tags": "access,switch,demo",
    },
    {
        "name": "Edge Firewall (demo)",
        "ip": "10.10.0.254",
        "port": 22,
        "username": "netaudit",
        "vendor_hint": "paloalto",
        "tags": "firewall,edge,demo",
    },
    {
        "name": "Linux Bastion (demo)",
        "ip": "10.10.5.7",
        "port": 22,
        "username": "netaudit",
        "vendor_hint": "linux",
        "tags": "server,bastion,demo",
    },
]


def _seed_demo_data() -> None:
    """Insert any missing demo devices. Idempotent — keyed by IP."""
    with session_scope() as session:
        existing_ips = {
            ip for (ip,) in session.execute(select(Device.ip)).all()
        }
        added = 0
        for entry in _DEMO_DEVICES:
            if entry["ip"] in existing_ips:
                continue
            session.add(Device(**entry))
            added += 1
        if added:
            log.info("Seeded %d demo device(s).", added)


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Starting %s v%s", settings.app_name, settings.app_version)
    init_db()
    if settings.seed_demo_data:
        _seed_demo_data()
    start_scheduler()
    try:
        yield
    finally:
        log.info("Shutting down %s", settings.app_name)
        shutdown_scheduler()


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="AI Network Intelligence & Monitoring Platform.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False,
)


@app.middleware("http")
async def no_cache_for_html(request, call_next):
    """Disable caching for HTML in development so reloads pick up changes."""
    response = await call_next(request)
    if request.url.path.endswith((".html", "/")) or request.url.path == "/app":
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return response


# ---------------------------------------------------------------------------
# Structured JSON error envelope (so the UI never sees a stack-trace HTML page)
# ---------------------------------------------------------------------------


def _error_envelope(status_code: int, code: str, message: str, **extra) -> JSONResponse:
    body = {
        "ok": False,
        "error": {"code": code, "message": message, **extra},
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
    return JSONResponse(status_code=status_code, content=body)


@app.exception_handler(StarletteHTTPException)
async def _http_exception(request: Request, exc: StarletteHTTPException):
    return _error_envelope(
        exc.status_code,
        code=f"http_{exc.status_code}",
        message=str(exc.detail) if exc.detail else "HTTP error",
    )


@app.exception_handler(RequestValidationError)
async def _validation_exception(request: Request, exc: RequestValidationError):
    return _error_envelope(
        422,
        code="validation_error",
        message="Request validation failed.",
        errors=exc.errors(),
    )


@app.exception_handler(Exception)
async def _unhandled_exception(request: Request, exc: Exception):
    log.error(
        "Unhandled exception on %s %s: %s\n%s",
        request.method,
        request.url.path,
        exc,
        traceback.format_exc(),
    )
    return _error_envelope(
        500,
        code="internal_error",
        message="An unexpected error occurred. Check server logs for details.",
    )


# ---------------------------------------------------------------------------
# API routes (all mounted under /api so the frontend can be served at /)
# ---------------------------------------------------------------------------
API_PREFIX = "/api"
app.include_router(devices.router, prefix=API_PREFIX)
app.include_router(scan.router, prefix=API_PREFIX)
app.include_router(insights.router, prefix=API_PREFIX)
app.include_router(alerts.router, prefix=API_PREFIX)
app.include_router(scheduler.router, prefix=API_PREFIX)
app.include_router(dashboard.router, prefix=API_PREFIX)
app.include_router(discover.router, prefix=API_PREFIX)
app.include_router(drift.router, prefix=API_PREFIX)
app.include_router(logs.router, prefix=API_PREFIX)


@app.get("/api/health")
def healthcheck() -> dict:
    return {
        "status": "ok",
        "app": settings.app_name,
        "version": settings.app_version,
        "time": datetime.utcnow().isoformat() + "Z",
    }


@app.get("/api")
def api_root() -> dict:
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "endpoints": [
            "GET    /api/health",
            "GET    /api/dashboard/stats",
            "GET    /api/devices",
            "POST   /api/devices",
            "PATCH  /api/devices/{id}",
            "DELETE /api/devices/{id}",
            "POST   /api/scan",
            "GET    /api/results",
            "GET    /api/insights",
            "GET    /api/insights/latest",
            "GET    /api/alerts",
            "POST   /api/scan/schedule",
            "GET    /api/scan/schedule",
            "DELETE /api/scan/schedule/{id}",
            "POST   /api/discover",
            "GET    /api/drift",
            "GET    /api/drift/stats",
            "GET    /api/logs/recent",
            "GET    /api/logs/stream  (SSE)",
        ],
    }


# ---------------------------------------------------------------------------
# Frontend static hosting
# ---------------------------------------------------------------------------
if (FRONTEND_DIR / "app" / "index.html").exists():
    # Serve subdirectories as static assets.
    for sub in ("styles", "components", "pages"):
        path = FRONTEND_DIR / sub
        if path.exists():
            app.mount(f"/{sub}", StaticFiles(directory=path), name=sub)
    app.mount(
        "/app", StaticFiles(directory=FRONTEND_DIR / "app", html=True), name="app"
    )

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(FRONTEND_DIR / "app" / "index.html")

else:

    @app.get("/")
    def fallback() -> JSONResponse:
        return JSONResponse(
            {
                "message": (
                    "NetAuditX backend is running but the frontend bundle was not "
                    "found. Browse /api for the API."
                )
            }
        )
