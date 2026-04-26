"""Network-drift event routes."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from backend.api.schemas import DriftEventOut
from backend.db.database import get_db
from backend.db.models import DriftEvent

router = APIRouter(tags=["drift"])


@router.get("/drift", response_model=list[DriftEventOut])
def list_drift(
    limit: int = Query(default=200, ge=1, le=2000),
    kind: Optional[str] = None,
    severity: Optional[str] = None,
    target: Optional[str] = None,
    db: Session = Depends(get_db),
) -> list[DriftEventOut]:
    stmt = select(DriftEvent).order_by(desc(DriftEvent.created_at)).limit(limit)
    if kind:
        stmt = stmt.where(DriftEvent.kind == kind)
    if severity:
        stmt = stmt.where(DriftEvent.severity == severity)
    if target:
        stmt = stmt.where(DriftEvent.target == target)
    rows = db.execute(stmt).scalars().all()
    return [
        DriftEventOut(
            id=r.id,
            kind=r.kind,
            severity=r.severity,
            target=r.target,
            details=r.details or {},
            snapshot_id=r.snapshot_id,
            created_at=r.created_at,
        )
        for r in rows
    ]


@router.get("/drift/stats")
def drift_stats(db: Session = Depends(get_db)) -> dict:
    total = db.scalar(select(func.count(DriftEvent.id))) or 0
    by_kind = db.execute(
        select(DriftEvent.kind, func.count(DriftEvent.id)).group_by(DriftEvent.kind)
    ).all()
    by_sev = db.execute(
        select(DriftEvent.severity, func.count(DriftEvent.id)).group_by(DriftEvent.severity)
    ).all()
    return {
        "total": total,
        "by_kind": {k: c for k, c in by_kind},
        "by_severity": {s: c for s, c in by_sev},
    }
