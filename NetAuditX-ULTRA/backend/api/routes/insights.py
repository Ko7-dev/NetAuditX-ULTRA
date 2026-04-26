"""AI insight routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from backend.ai.analyzer import analyze
from backend.api.schemas import InsightOut
from backend.db.database import get_db
from backend.db.models import Insight, ScanResult

router = APIRouter(prefix="/insights", tags=["insights"])


@router.get("", response_model=list[InsightOut])
def list_insights(
    limit: int = Query(default=20, ge=1, le=200),
    db: Session = Depends(get_db),
) -> list[InsightOut]:
    rows = (
        db.execute(select(Insight).order_by(desc(Insight.created_at)).limit(limit))
        .scalars()
        .all()
    )
    return [
        InsightOut(
            id=r.id,
            summary=r.summary,
            risk_score=r.risk_score,
            anomalies=r.anomalies or [],
            recommendations=r.recommendations or [],
            devices_total=r.devices_total,
            devices_failed=r.devices_failed,
            source=r.source,
            created_at=r.created_at,
        )
        for r in rows
    ]


@router.get("/latest")
def latest_insight(db: Session = Depends(get_db)) -> dict:
    row = db.execute(
        select(Insight).order_by(desc(Insight.created_at)).limit(1)
    ).scalar_one_or_none()
    if row:
        return {
            "id": row.id,
            "summary": row.summary,
            "risk_score": row.risk_score,
            "anomalies": row.anomalies or [],
            "recommendations": row.recommendations or [],
            "devices_total": row.devices_total,
            "devices_failed": row.devices_failed,
            "source": row.source,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }

    # No history yet — synthesize an empty insight from current state.
    last_results = (
        db.execute(select(ScanResult).order_by(desc(ScanResult.created_at)).limit(50))
        .scalars()
        .all()
    )
    payload = analyze(
        db,
        [
            {
                "ip": r.ip,
                "status": r.status,
                "vendor": r.vendor,
                "uptime_seconds": r.uptime_seconds,
                "error": r.error,
            }
            for r in last_results
        ],
    )
    payload["created_at"] = None
    return payload
