"""Scan-related routes (trigger scans, fetch scan results)."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from backend.ai.analyzer import analyze
from backend.alerts.manager import emit_alerts_for_scan
from backend.api.schemas import ScanRequest, ScanResponse, ScanResultOut
from backend.core.drift import detect_drift, new_snapshot_id, persist_snapshot
from backend.core.ssh_engine import ScanTarget, scan_targets
from backend.db.database import get_db
from backend.db.models import Device, Insight, OpenPort, ScanResult
from backend.utils.logger import get_logger

router = APIRouter(tags=["scans"])
log = get_logger("netauditx.api.scan")


def _build_targets(
    db: Session, payload: ScanRequest
) -> list[ScanTarget]:
    if payload.targets:
        # Look up matching device records (if any) to inherit creds.
        devices_by_ip = {
            d.ip: d
            for d in db.execute(
                select(Device).where(Device.ip.in_(payload.targets))
            ).scalars()
        }
        out: list[ScanTarget] = []
        for ip in payload.targets:
            d = devices_by_ip.get(ip)
            out.append(
                ScanTarget(
                    ip=ip,
                    port=d.port if d else payload.port,
                    username=(d.username if d and d.username else payload.username),
                    password=(d.password if d and d.password else payload.password),
                    vendor_hint=d.vendor_hint if d else None,
                    name=d.name if d else None,
                )
            )
        return out

    # No explicit targets — scan every enabled device.
    devices = db.execute(
        select(Device).where(Device.enabled.is_(True))
    ).scalars().all()
    return [
        ScanTarget(
            ip=d.ip,
            port=d.port,
            username=d.username,
            password=d.password,
            vendor_hint=d.vendor_hint,
            name=d.name,
        )
        for d in devices
    ]


@router.post("/scan", response_model=ScanResponse)
async def trigger_scan(
    payload: ScanRequest, db: Session = Depends(get_db)
) -> ScanResponse:
    targets = _build_targets(db, payload)
    if not targets:
        raise HTTPException(
            status_code=400,
            detail="No scan targets provided and no enabled devices configured.",
        )

    results = await scan_targets(targets)
    result_dicts = [r.to_dict() for r in results]

    # Persist scan rows
    devices_by_ip = {d.ip: d for d in db.execute(select(Device)).scalars()}
    for r in results:
        db.add(
            ScanResult(
                device_id=devices_by_ip.get(r.ip).id if r.ip in devices_by_ip else None,
                ip=r.ip,
                status=r.status,
                vendor=r.vendor,
                uptime_seconds=r.uptime_seconds,
                raw_output=r.raw_output,
                error=r.error,
                duration_ms=r.duration_ms,
            )
        )

    # Pull the most recent open-port snapshot per IP we just scanned so the
    # analyzer can fold port-vulnerability scoring into the risk score.
    scanned_ips = [r.ip for r in results]
    port_rows: list[OpenPort] = []
    if scanned_ips:
        latest_snapshot_row = db.execute(
            select(OpenPort.snapshot_id)
            .order_by(desc(OpenPort.created_at))
            .limit(1)
        ).first()
        if latest_snapshot_row:
            port_rows = list(
                db.execute(
                    select(OpenPort).where(
                        OpenPort.snapshot_id == latest_snapshot_row[0],
                        OpenPort.ip.in_(scanned_ips),
                    )
                ).scalars()
            )
    open_ports_dicts = [
        {"ip": p.ip, "port": p.port, "banner": p.banner or ""} for p in port_rows
    ]

    insight = analyze(db, result_dicts, open_ports=open_ports_dicts)
    db.add(
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

    # If the scan also surfaced ports (raw_output may include 'open_ports'
    # entries from richer SSH parsers), persist them as a new snapshot and
    # run drift detection so the scan→drift→alert pipeline closes the loop.
    inline_ports: list[dict] = []
    for r in results:
        for p in getattr(r, "open_ports", None) or []:
            inline_ports.append(
                {
                    "ip": r.ip,
                    "port": int(p.get("port")),
                    "service": p.get("service") or "unknown",
                    "banner": p.get("banner") or "",
                    "severity": p.get("severity") or "info",
                    "risk_score": int(p.get("risk_score") or 0),
                }
            )
    drift_count = 0
    if inline_ports:
        snap = new_snapshot_id()
        host_groups: dict[str, list[dict]] = {}
        for p in inline_ports:
            host_groups.setdefault(p["ip"], []).append(p)
        persist_snapshot(
            db,
            snap,
            [{"ip": ip, "open_ports": ps} for ip, ps in host_groups.items()],
        )
        drift_count = len(detect_drift(db, snap))

    db.commit()

    emitted = await emit_alerts_for_scan(result_dicts, insight)

    return ScanResponse(
        scanned=len(results),
        success=sum(1 for r in results if r.status == "success"),
        failed=sum(1 for r in results if r.status != "success"),
        results=result_dicts,
        insight=insight,
        alerts_emitted=len(emitted),
        drift_events=drift_count,
    )


@router.get("/results", response_model=list[ScanResultOut])
def list_results(
    limit: int = Query(default=100, ge=1, le=1000),
    ip: Optional[str] = None,
    status_filter: Optional[str] = Query(default=None, alias="status"),
    db: Session = Depends(get_db),
) -> list[ScanResultOut]:
    stmt = select(ScanResult).order_by(desc(ScanResult.created_at)).limit(limit)
    if ip:
        stmt = stmt.where(ScanResult.ip == ip)
    if status_filter:
        stmt = stmt.where(ScanResult.status == status_filter)
    rows = db.execute(stmt).scalars().all()
    return [
        ScanResultOut(
            id=r.id,
            device_id=r.device_id,
            ip=r.ip,
            status=r.status,
            vendor=r.vendor,
            uptime_seconds=r.uptime_seconds,
            raw_output=r.raw_output,
            error=r.error,
            duration_ms=r.duration_ms,
            created_at=r.created_at,
        )
        for r in rows
    ]


@router.get("/results/stats")
def results_stats(db: Session = Depends(get_db)) -> dict:
    total = db.scalar(select(func.count(ScanResult.id))) or 0
    by_status_rows = db.execute(
        select(ScanResult.status, func.count(ScanResult.id)).group_by(ScanResult.status)
    ).all()
    return {
        "total": total,
        "by_status": {row[0]: row[1] for row in by_status_rows},
    }
