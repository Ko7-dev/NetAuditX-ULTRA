"""Dashboard summary route — single payload powering the overview page."""

from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from backend.api.schemas import DashboardStats
from backend.db.database import get_db
from backend.db.models import Alert, Device, Insight, ScanResult

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats", response_model=DashboardStats)
def stats(db: Session = Depends(get_db)) -> DashboardStats:
    cutoff = datetime.utcnow() - timedelta(hours=24)

    total = db.scalar(select(func.count(Device.id))) or 0
    enabled = db.scalar(
        select(func.count(Device.id)).where(Device.enabled.is_(True))
    ) or 0

    # Latest result per IP
    latest_subq = (
        select(ScanResult.ip, func.max(ScanResult.created_at).label("ts"))
        .group_by(ScanResult.ip)
        .subquery()
    )
    latest_rows = db.execute(
        select(ScanResult)
        .join(
            latest_subq,
            (ScanResult.ip == latest_subq.c.ip)
            & (ScanResult.created_at == latest_subq.c.ts),
        )
    ).scalars().all()

    online = sum(1 for r in latest_rows if r.status == "success")
    offline = sum(1 for r in latest_rows if r.status != "success")

    scans_24h = db.scalar(
        select(func.count(ScanResult.id)).where(ScanResult.created_at >= cutoff)
    ) or 0
    failures_24h = db.scalar(
        select(func.count(ScanResult.id)).where(
            ScanResult.created_at >= cutoff, ScanResult.status != "success"
        )
    ) or 0

    last_insight = db.execute(
        select(Insight).order_by(desc(Insight.created_at)).limit(1)
    ).scalar_one_or_none()
    risk_score = last_insight.risk_score if last_insight else 0

    last_scan_at = db.scalar(select(func.max(ScanResult.created_at)))

    open_alerts = db.scalar(
        select(func.count(Alert.id)).where(Alert.created_at >= cutoff)
    ) or 0

    vendor_rows = db.execute(
        select(ScanResult.vendor, func.count(ScanResult.id))
        .where(ScanResult.created_at >= cutoff, ScanResult.vendor.is_not(None))
        .group_by(ScanResult.vendor)
    ).all()
    vendors = {row[0]: row[1] for row in vendor_rows}

    return DashboardStats(
        devices_total=total,
        devices_enabled=enabled,
        devices_online=online,
        devices_offline=offline,
        scans_24h=scans_24h,
        failures_24h=failures_24h,
        risk_score=risk_score,
        last_scan_at=last_scan_at,
        open_alerts_24h=open_alerts,
        vendors=vendors,
    )
