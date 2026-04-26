"""Alert manager: deduplication, severity, persistence and dispatch."""

from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.alerts.email_sender import send_email
from backend.alerts.webhook_sender import send_webhook
from backend.config import get_settings
from backend.db.database import session_scope
from backend.db.models import Alert
from backend.utils.logger import get_logger

log = get_logger("netauditx.alerts")


SEVERITIES = ("info", "warning", "critical")


def _fingerprint(severity: str, title: str, target: str | None) -> str:
    raw = f"{severity}|{title}|{target or ''}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def _was_recently_sent(session: Session, fingerprint: str) -> bool:
    settings = get_settings()
    cutoff = datetime.utcnow() - timedelta(
        minutes=settings.alert_dedup_window_minutes
    )
    existing = session.execute(
        select(Alert)
        .where(Alert.fingerprint == fingerprint)
        .where(Alert.created_at >= cutoff)
        .limit(1)
    ).scalar_one_or_none()
    return existing is not None


async def _deliver(alert: dict) -> tuple[bool, bool]:
    """Best-effort send to email + webhook in parallel."""
    payload = {
        "severity": alert["severity"],
        "title": alert["title"],
        "message": alert["message"],
        "target": alert.get("target"),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
    body_text = (
        f"[{alert['severity'].upper()}] {alert['title']}\n"
        f"Target: {alert.get('target') or 'N/A'}\n\n{alert['message']}\n"
    )
    email_ok, hook_ok = await asyncio.gather(
        send_email(f"NetAuditX: {alert['title']}", body_text),
        send_webhook(payload),
        return_exceptions=False,
    )
    return bool(email_ok), bool(hook_ok)


async def emit_alert(
    severity: str,
    title: str,
    message: str,
    target: str | None = None,
) -> dict[str, Any] | None:
    """Persist + dispatch a single alert with dedup."""
    if severity not in SEVERITIES:
        severity = "info"
    fp = _fingerprint(severity, title, target)

    with session_scope() as session:
        if _was_recently_sent(session, fp):
            log.debug("Alert %s suppressed by dedup window", fp)
            return None

    email_ok, hook_ok = await _deliver(
        {"severity": severity, "title": title, "message": message, "target": target}
    )

    with session_scope() as session:
        row = Alert(
            severity=severity,
            title=title,
            message=message,
            target=target,
            fingerprint=fp,
            delivered_email=email_ok,
            delivered_webhook=hook_ok,
        )
        session.add(row)
        session.flush()
        return {
            "id": row.id,
            "severity": row.severity,
            "title": row.title,
            "message": row.message,
            "target": row.target,
            "fingerprint": row.fingerprint,
            "delivered_email": row.delivered_email,
            "delivered_webhook": row.delivered_webhook,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }


async def emit_alerts_for_scan(
    scan_results: list[dict],
    insight: dict[str, Any],
) -> list[dict]:
    """Translate a scan + insight into one or more alerts."""
    settings = get_settings()
    emitted: list[dict] = []

    # Per-device offline alerts
    for r in scan_results:
        if r.get("status") in ("offline", "failed"):
            res = await emit_alert(
                "warning",
                f"Device unreachable: {r['ip']}",
                f"Status={r['status']} | error={r.get('error') or 'n/a'}",
                target=r["ip"],
            )
            if res:
                emitted.append(res)

    # Threshold-based: too many failures in one scan
    failed_count = sum(1 for r in scan_results if r.get("status") != "success")
    if failed_count >= settings.alert_failure_threshold:
        res = await emit_alert(
            "critical",
            f"Failure threshold exceeded ({failed_count} devices)",
            f"{failed_count} devices failed in the latest scan "
            f"(threshold={settings.alert_failure_threshold}).",
            target="network",
        )
        if res:
            emitted.append(res)

    # Risk-score alert
    risk = int(insight.get("risk_score", 0))
    if risk >= settings.alert_risk_score_threshold:
        res = await emit_alert(
            "critical",
            f"High network risk score ({risk}/100)",
            insight.get("summary", ""),
            target="network",
        )
        if res:
            emitted.append(res)

    # Anomaly-driven alerts
    for a in insight.get("anomalies", []):
        res = await emit_alert(
            a.get("severity", "warning"),
            f"Anomaly: {a.get('type', 'unknown')}",
            a.get("message", ""),
            target=a.get("target"),
        )
        if res:
            emitted.append(res)

    return emitted
