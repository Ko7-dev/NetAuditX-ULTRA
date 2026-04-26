"""SMTP-based email alert sender."""

from __future__ import annotations

from email.message import EmailMessage

import aiosmtplib

from backend.config import get_settings
from backend.utils.logger import get_logger

log = get_logger("netauditx.alerts.email")


async def send_email(subject: str, body: str) -> bool:
    settings = get_settings()
    if not (settings.smtp_host and settings.alert_email_from and settings.alert_email_to):
        log.debug("Email alerts not configured — skipping.")
        return False

    msg = EmailMessage()
    msg["From"] = settings.alert_email_from
    msg["To"] = settings.alert_email_to
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        await aiosmtplib.send(
            msg,
            hostname=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_username or None,
            password=settings.smtp_password or None,
            start_tls=settings.smtp_use_tls,
            timeout=15,
        )
        log.info("Email alert delivered to %s", settings.alert_email_to)
        return True
    except Exception as exc:  # noqa: BLE001
        log.warning("Email delivery failed: %s", exc)
        return False
