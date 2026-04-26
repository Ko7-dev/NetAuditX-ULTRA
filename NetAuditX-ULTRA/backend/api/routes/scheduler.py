"""Scheduler routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.api.schemas import ScheduleCreate, ScheduleOut
from backend.db.database import get_db
from backend.db.models import ScheduledJob
from backend.scheduler.scheduler import register_or_update_job, remove_job

router = APIRouter(prefix="/scan", tags=["scheduler"])


@router.post("/schedule", response_model=ScheduleOut, status_code=201)
def create_schedule(payload: ScheduleCreate) -> ScheduleOut:
    job = register_or_update_job(
        name=payload.name,
        interval_minutes=payload.interval_minutes,
        targets=payload.targets,
    )
    return ScheduleOut(**job)


@router.get("/schedule", response_model=list[ScheduleOut])
def list_schedules(db: Session = Depends(get_db)) -> list[ScheduleOut]:
    rows = db.execute(select(ScheduledJob).order_by(ScheduledJob.name)).scalars().all()
    return [
        ScheduleOut(
            id=r.id,
            name=r.name,
            interval_minutes=r.interval_minutes,
            targets=r.targets or [],
            enabled=r.enabled,
            last_run_at=r.last_run_at,
        )
        for r in rows
    ]


@router.delete("/schedule/{job_id}", status_code=204)
def delete_schedule(job_id: int) -> None:
    if not remove_job(job_id):
        raise HTTPException(status_code=404, detail="Schedule not found")
    return None
