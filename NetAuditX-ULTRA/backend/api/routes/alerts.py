"""Alert routes."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from backend.api.schemas import AlertOut
from backend.db.database import get_db
from backend.db.models import Alert

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertOut])
def list_alerts(
    limit: int = Query(default=100, ge=1, le=1000),
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
) -> list[AlertOut]:
    stmt = select(Alert).order_by(desc(Alert.created_at)).limit(limit)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    rows = db.execute(stmt).scalars().all()
    return [
        AlertOut(
            id=r.id,
            severity=r.severity,
            title=r.title,
            message=r.message,
            target=r.target,
            fingerprint=r.fingerprint,
            delivered_email=r.delivered_email,
            delivered_webhook=r.delivered_webhook,
            created_at=r.created_at,
        )
        for r in rows
    ]
