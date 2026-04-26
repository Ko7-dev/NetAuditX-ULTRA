"""Anomaly detection over scan history."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.db.models import ScanResult


def detect_anomalies(
    session: Session,
    current_results: Iterable[dict],
    window_hours: int = 24,
) -> list[dict]:
    """Compare current scan results to recent history.

    Returns a list of anomaly dicts:
        { type, severity, target, message }
    """
    anomalies: list[dict] = []
    cutoff = datetime.utcnow() - timedelta(hours=window_hours)

    history = (
        session.execute(
            select(ScanResult).where(ScanResult.created_at >= cutoff)
        )
        .scalars()
        .all()
    )

    by_ip: dict[str, list[ScanResult]] = defaultdict(list)
    for row in history:
        by_ip[row.ip].append(row)

    # 1. Flap detection: status changes >= 3 times in window
    for ip, rows in by_ip.items():
        statuses = [r.status for r in rows]
        if len(statuses) >= 4:
            transitions = sum(
                1 for a, b in zip(statuses, statuses[1:]) if a != b
            )
            if transitions >= 3:
                anomalies.append(
                    {
                        "type": "flapping_device",
                        "severity": "warning",
                        "target": ip,
                        "message": (
                            f"{ip} status changed {transitions} times in the "
                            f"last {window_hours}h — possible flapping link."
                        ),
                    }
                )

    # 2. Sudden uptime reset: previous uptime higher than current
    for r in current_results:
        if r.get("status") != "success" or r.get("uptime_seconds") is None:
            continue
        prior = next(
            (
                p
                for p in by_ip.get(r["ip"], [])
                if p.uptime_seconds is not None
            ),
            None,
        )
        if prior and prior.uptime_seconds and r["uptime_seconds"] < prior.uptime_seconds - 600:
            anomalies.append(
                {
                    "type": "uptime_reset",
                    "severity": "warning",
                    "target": r["ip"],
                    "message": (
                        f"{r['ip']} appears to have rebooted (uptime dropped "
                        f"from {prior.uptime_seconds}s to {r['uptime_seconds']}s)."
                    ),
                }
            )

    # 3. Repeated authentication failures
    auth_failures = [
        r
        for r in history
        if r.error and "authentication" in r.error.lower()
    ]
    counts = Counter(r.ip for r in auth_failures)
    for ip, count in counts.items():
        if count >= 3:
            anomalies.append(
                {
                    "type": "repeated_auth_failure",
                    "severity": "critical",
                    "target": ip,
                    "message": (
                        f"{count} authentication failures against {ip} in the "
                        f"last {window_hours}h — possible credential issue or "
                        f"brute-force activity."
                    ),
                }
            )

    # 4. Mass-failure event
    failed_now = [r for r in current_results if r.get("status") != "success"]
    if current_results and len(failed_now) / max(1, len(list(current_results))) >= 0.5:
        anomalies.append(
            {
                "type": "mass_failure",
                "severity": "critical",
                "target": "network",
                "message": (
                    f"{len(failed_now)} of {len(list(current_results))} devices "
                    f"failed in this scan — possible network outage."
                ),
            }
        )

    return anomalies
