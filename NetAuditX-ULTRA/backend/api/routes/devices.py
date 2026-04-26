"""Device CRUD routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import desc, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.api.schemas import DeviceCreate, DeviceOut, DeviceUpdate
from backend.db.database import get_db
from backend.db.models import Device, ScanResult

router = APIRouter(prefix="/devices", tags=["devices"])


def _serialize(device: Device, last: ScanResult | None) -> DeviceOut:
    return DeviceOut(
        id=device.id,
        name=device.name,
        ip=device.ip,
        port=device.port,
        username=device.username,
        vendor_hint=device.vendor_hint,
        enabled=device.enabled,
        tags=device.tags,
        last_status=last.status if last else None,
        last_seen_at=last.created_at if last else None,
        created_at=device.created_at,
    )


@router.get("", response_model=list[DeviceOut])
def list_devices(db: Session = Depends(get_db)) -> list[DeviceOut]:
    devices = db.execute(select(Device).order_by(Device.name)).scalars().all()
    out: list[DeviceOut] = []
    for d in devices:
        last = db.execute(
            select(ScanResult)
            .where(ScanResult.ip == d.ip)
            .order_by(desc(ScanResult.created_at))
            .limit(1)
        ).scalar_one_or_none()
        out.append(_serialize(d, last))
    return out


@router.post("", response_model=DeviceOut, status_code=status.HTTP_201_CREATED)
def create_device(payload: DeviceCreate, db: Session = Depends(get_db)) -> DeviceOut:
    device = Device(**payload.model_dump())
    db.add(device)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Device with ip {payload.ip} already exists",
        ) from exc
    db.refresh(device)
    return _serialize(device, None)


@router.patch("/{device_id}", response_model=DeviceOut)
def update_device(
    device_id: int, payload: DeviceUpdate, db: Session = Depends(get_db)
) -> DeviceOut:
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(device, field, value)
    db.commit()
    db.refresh(device)
    last = db.execute(
        select(ScanResult)
        .where(ScanResult.ip == device.ip)
        .order_by(desc(ScanResult.created_at))
        .limit(1)
    ).scalar_one_or_none()
    return _serialize(device, last)


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_device(device_id: int, db: Session = Depends(get_db)) -> None:
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    db.delete(device)
    db.commit()
    return None
