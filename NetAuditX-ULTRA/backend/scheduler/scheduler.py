"""APScheduler integration for periodic scanning."""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import select

from backend.alerts.manager import emit_alerts_for_scan
from backend.ai.analyzer import analyze
from backend.config import get_settings
from backend.core.ssh_engine import ScanTarget, scan_targets
from backend.db.database import session_scope
from backend.db.models import Device, Insight, ScanResult, ScheduledJob
from backend.utils.logger import get_logger

log = get_logger("netauditx.scheduler")


_scheduler: Optional[AsyncIOScheduler] = None


def get_scheduler() -> AsyncIOScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = AsyncIOScheduler(timezone="UTC")
    return _scheduler


# ---------------------------------------------------------------------------
# Job runner
# ---------------------------------------------------------------------------


async def _execute_job(job_id: int) -> None:
    """Execute a single scheduled scan job."""
    log.info("Scheduled job %s firing", job_id)

    with session_scope() as session:
        job = session.get(ScheduledJob, job_id)
        if not job or not job.enabled:
            log.info("Job %s missing or disabled", job_id)
            return

        targets = list(job.targets or [])
        # If no explicit targets, scan all enabled devices.
        if not targets:
            targets = [
                d.ip
                for d in session.execute(
                    select(Device).where(Device.enabled.is_(True))
                ).scalars()
            ]

        device_lookup = {
            d.ip: d
            for d in session.execute(select(Device)).scalars()
        }

    scan_specs = [
        ScanTarget(
            ip=ip,
            port=device_lookup[ip].port if ip in device_lookup else 22,
            username=device_lookup[ip].username if ip in device_lookup else None,
            password=device_lookup[ip].password if ip in device_lookup else None,
            vendor_hint=device_lookup[ip].vendor_hint if ip in device_lookup else None,
            name=device_lookup[ip].name if ip in device_lookup else None,
        )
        for ip in targets
    ]

    if not scan_specs:
        log.info("Job %s has no targets to scan", job_id)
        with session_scope() as session:
            j = session.get(ScheduledJob, job_id)
            if j:
                j.last_run_at = datetime.utcnow()
        return

    results = await scan_targets(scan_specs)
    result_dicts = [r.to_dict() for r in results]

    with session_scope() as session:
        for r in results:
            session.add(
                ScanResult(
                    device_id=device_lookup[r.ip].id if r.ip in device_lookup else None,
                    ip=r.ip,
                    status=r.status,
                    vendor=r.vendor,
                    uptime_seconds=r.uptime_seconds,
                    raw_output=r.raw_output,
                    error=r.error,
                    duration_ms=r.duration_ms,
                )
            )

        insight = analyze(session, result_dicts)
        session.add(
            Insight(
                summary=insight["summary"],
                risk_score=insight["risk_score"],
                anomalies=insight["anomalies"],
                recommendations=insight["recommendations"],
                devices_total=insight["devices_total"],
                devices_failed=insight["devices_failed"],
                source=insight["source"],
            )
        )
        j = session.get(ScheduledJob, job_id)
        if j:
            j.last_run_at = datetime.utcnow()

    await emit_alerts_for_scan(result_dicts, insight)


def _wrap_async(coro_factory):
    def runner():
        asyncio.create_task(coro_factory())
    return runner


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def start_scheduler() -> None:
    settings = get_settings()
    if not settings.scheduler_enabled:
        log.info("Scheduler disabled by config")
        return

    sched = get_scheduler()
    if sched.running:
        return
    sched.start()
    log.info("APScheduler started")

    # Re-register all enabled jobs from DB
    with session_scope() as session:
        jobs = session.execute(select(ScheduledJob)).scalars().all()
        for j in jobs:
            if j.enabled:
                _add_job_to_scheduler(j.id, j.interval_minutes)


def shutdown_scheduler() -> None:
    sched = get_scheduler()
    if sched.running:
        sched.shutdown(wait=False)
        log.info("APScheduler stopped")


def _add_job_to_scheduler(job_id: int, interval_minutes: int) -> None:
    sched = get_scheduler()
    job_key = f"netauditx-job-{job_id}"
    if sched.get_job(job_key):
        sched.remove_job(job_key)
    sched.add_job(
        _wrap_async(lambda: _execute_job(job_id)),
        trigger=IntervalTrigger(minutes=max(1, interval_minutes)),
        id=job_key,
        name=f"NetAuditX scheduled scan {job_id}",
        replace_existing=True,
    )
    log.info(
        "Registered scheduled job %s every %d minute(s)", job_id, interval_minutes
    )


def register_or_update_job(
    name: str, interval_minutes: int, targets: list[str]
) -> dict:
    """Create or update a scheduled job and register with APScheduler."""
    with session_scope() as session:
        existing = session.execute(
            select(ScheduledJob).where(ScheduledJob.name == name)
        ).scalar_one_or_none()
        if existing:
            existing.interval_minutes = interval_minutes
            existing.targets = targets
            existing.enabled = True
            session.flush()
            job = existing
        else:
            job = ScheduledJob(
                name=name,
                interval_minutes=interval_minutes,
                targets=targets,
                enabled=True,
            )
            session.add(job)
            session.flush()
        job_payload = {
            "id": job.id,
            "name": job.name,
            "interval_minutes": job.interval_minutes,
            "targets": job.targets,
            "enabled": job.enabled,
            "last_run_at": job.last_run_at.isoformat() if job.last_run_at else None,
        }

    _add_job_to_scheduler(job_payload["id"], interval_minutes)
    return job_payload


def remove_job(job_id: int) -> bool:
    sched = get_scheduler()
    job_key = f"netauditx-job-{job_id}"
    if sched.get_job(job_key):
        sched.remove_job(job_key)
    with session_scope() as session:
        job = session.get(ScheduledJob, job_id)
        if not job:
            return False
        session.delete(job)
    log.info("Removed scheduled job %s", job_id)
    return True
