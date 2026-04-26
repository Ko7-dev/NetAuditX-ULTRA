"""Network-discovery routes."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.alerts.manager import emit_alert
from backend.api.schemas import DiscoveryRequest, DiscoveryResponse
from backend.core.discovery import discover_subnet
from backend.core.drift import detect_drift, new_snapshot_id, persist_snapshot
from backend.db.database import get_db
from backend.db.models import Device
from backend.utils.logger import get_logger

router = APIRouter(tags=["discovery"])
log = get_logger("netauditx.api.discover")


def _persist_devices(
    db: Session,
    discovered: list[dict],
) -> int:
    """Insert any newly discovered host into the device inventory."""
    existing = {d.ip: d for d in db.execute(select(Device)).scalars()}
    added = 0
    now = datetime.utcnow()
    for h in discovered:
        ip = h["ip"]
        device = existing.get(ip)
        if device:
            device.mac_address = h.get("mac") or device.mac_address
            device.hostname = h.get("hostname") or device.hostname
            device.last_latency_ms = h.get("latency_ms") or device.last_latency_ms
            device.discovered_at = now
            device.discovery_source = h.get("source")
        else:
            db.add(
                Device(
                    name=h.get("hostname") or f"discovered-{ip}",
                    ip=ip,
                    port=22,
                    mac_address=h.get("mac"),
                    hostname=h.get("hostname"),
                    last_latency_ms=h.get("latency_ms"),
                    discovered_at=now,
                    discovery_source=h.get("source"),
                    enabled=True,
                    tags="discovered",
                )
            )
            added += 1
    return added


@router.post("/discover", response_model=DiscoveryResponse)
async def run_discovery(
    payload: DiscoveryRequest, db: Session = Depends(get_db)
) -> DiscoveryResponse:
    try:
        report = await discover_subnet(
            payload.cidr,
            ports=payload.ports,
            timeout=payload.timeout,
            max_concurrency=payload.max_concurrency,
            use_arp=payload.use_arp,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        log.exception("Discovery failed")
        raise HTTPException(status_code=500, detail=f"Discovery failed: {exc}") from exc

    hosts_dicts = [h.to_dict() for h in report.hosts]

    snapshot_id = new_snapshot_id()
    persist_snapshot(db, snapshot_id, hosts_dicts)
    drift_events = detect_drift(db, snapshot_id)

    devices_added = 0
    if payload.persist:
        devices_added = _persist_devices(db, hosts_dicts)

    db.commit()

    # Fire critical alert if a brand-new device showed up.
    new_dev_events = [e for e in drift_events if e.kind == "new_device"]
    for ev in new_dev_events[:5]:
        await emit_alert(
            "critical",
            f"New device on network: {ev.target}",
            f"Detected {len((ev.details or {}).get('ports', []))} open port(s) on a previously-unknown host.",
            target=ev.target,
        )

    return DiscoveryResponse(
        cidr=report.cidr,
        method=report.method,
        duration_ms=report.duration_ms,
        hosts_total=report.hosts_total,
        hosts=hosts_dicts,
        drift_events=len(drift_events),
        snapshot_id=snapshot_id,
        devices_added=devices_added,
    )
