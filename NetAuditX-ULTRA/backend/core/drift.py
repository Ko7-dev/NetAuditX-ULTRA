"""Network-drift detection.

Compares the most recent open-port snapshot against the previous one and
emits drift events when:

  * a brand-new device shows up on the network (`new_device`)
  * a previously-known device disappears (`gone_device`)
  * a new port opens on a known device (`new_port`)
  * a port that used to be open is now closed (`closed_port`)
  * the service banner of an existing port changed (`service_changed`)
"""

from __future__ import annotations

import uuid
from typing import Iterable

from sqlalchemy import desc, distinct, select
from sqlalchemy.orm import Session

from backend.db.models import DriftEvent, OpenPort
from backend.utils.logger import get_logger

log = get_logger("netauditx.drift")


def new_snapshot_id() -> str:
    return uuid.uuid4().hex[:16]


def persist_snapshot(
    session: Session,
    snapshot_id: str,
    discovered: Iterable[dict],
) -> int:
    """Persist a discovery report's open-port rows under one snapshot id."""
    count = 0
    for host in discovered:
        ip = host.get("ip")
        if not ip:
            continue
        for p in host.get("open_ports", []) or []:
            session.add(
                OpenPort(
                    ip=ip,
                    port=int(p["port"]),
                    protocol="tcp",
                    service=p.get("service") or "unknown",
                    banner=(p.get("banner") or "")[:1000],
                    risk_score=int(p.get("risk_score") or 0),
                    severity=p.get("severity") or "info",
                    snapshot_id=snapshot_id,
                )
            )
            count += 1
    session.flush()
    log.info("Persisted snapshot %s: %d open-port rows", snapshot_id, count)
    return count


def _previous_snapshot_id(session: Session, current: str) -> str | None:
    row = session.execute(
        select(OpenPort.snapshot_id, OpenPort.created_at)
        .where(OpenPort.snapshot_id != current)
        .order_by(desc(OpenPort.created_at))
        .limit(1)
    ).first()
    return row[0] if row else None


def _ports_for_snapshot(session: Session, snapshot_id: str) -> dict[str, dict[int, OpenPort]]:
    rows = session.execute(
        select(OpenPort).where(OpenPort.snapshot_id == snapshot_id)
    ).scalars()
    out: dict[str, dict[int, OpenPort]] = {}
    for r in rows:
        out.setdefault(r.ip, {})[r.port] = r
    return out


def detect_drift(
    session: Session,
    snapshot_id: str,
) -> list[DriftEvent]:
    """Compare the latest snapshot against the previous one and persist events."""
    prev = _previous_snapshot_id(session, snapshot_id)
    if not prev:
        log.info("No previous snapshot — skipping drift comparison.")
        return []

    current_map = _ports_for_snapshot(session, snapshot_id)
    prev_map = _ports_for_snapshot(session, prev)

    events: list[DriftEvent] = []

    # New / gone devices
    for ip in current_map.keys() - prev_map.keys():
        events.append(
            DriftEvent(
                kind="new_device",
                severity="warning",
                target=ip,
                details={
                    "ports": sorted(current_map[ip].keys()),
                    "snapshot_prev": prev,
                },
                snapshot_id=snapshot_id,
            )
        )
    for ip in prev_map.keys() - current_map.keys():
        events.append(
            DriftEvent(
                kind="gone_device",
                severity="warning",
                target=ip,
                details={
                    "last_ports": sorted(prev_map[ip].keys()),
                    "snapshot_prev": prev,
                },
                snapshot_id=snapshot_id,
            )
        )

    # Port-level diffs for shared devices
    for ip in current_map.keys() & prev_map.keys():
        cur_ports = current_map[ip]
        prv_ports = prev_map[ip]

        for port in cur_ports.keys() - prv_ports.keys():
            entry = cur_ports[port]
            events.append(
                DriftEvent(
                    kind="new_port",
                    severity="critical" if entry.severity == "critical" else "warning",
                    target=ip,
                    details={
                        "port": port,
                        "service": entry.service,
                        "banner": entry.banner,
                        "risk_score": entry.risk_score,
                    },
                    snapshot_id=snapshot_id,
                )
            )

        for port in prv_ports.keys() - cur_ports.keys():
            entry = prv_ports[port]
            events.append(
                DriftEvent(
                    kind="closed_port",
                    severity="info",
                    target=ip,
                    details={
                        "port": port,
                        "service": entry.service,
                    },
                    snapshot_id=snapshot_id,
                )
            )

        for port in cur_ports.keys() & prv_ports.keys():
            cur = cur_ports[port]
            prv = prv_ports[port]
            if (cur.banner or "") != (prv.banner or ""):
                events.append(
                    DriftEvent(
                        kind="service_changed",
                        severity="warning",
                        target=ip,
                        details={
                            "port": port,
                            "service": cur.service,
                            "banner_before": (prv.banner or "")[:200],
                            "banner_after": (cur.banner or "")[:200],
                        },
                        snapshot_id=snapshot_id,
                    )
                )

    for ev in events:
        session.add(ev)
    session.flush()

    log.info(
        "Drift detection: %d events vs snapshot %s",
        len(events),
        prev,
    )
    return events


def list_recent_snapshots(session: Session, limit: int = 10) -> list[str]:
    rows = session.execute(
        select(distinct(OpenPort.snapshot_id))
        .order_by(desc(OpenPort.snapshot_id))
        .limit(limit)
    ).all()
    return [r[0] for r in rows]
