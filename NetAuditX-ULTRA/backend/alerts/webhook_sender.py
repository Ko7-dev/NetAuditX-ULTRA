"""Generic JSON webhook alert sender."""

from __future__ import annotations

from typing import Any

import httpx

from backend.config import get_settings
from backend.utils.logger import get_logger

log = get_logger("netauditx.alerts.webhook")


async def send_webhook(payload: dict[str, Any]) -> bool:
    settings = get_settings()
    if not settings.alert_webhook_url:
        log.debug("Webhook alerts not configured — skipping.")
        return False

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(settings.alert_webhook_url, json=payload)
        if resp.is_success:
            log.info("Webhook alert delivered (%s)", resp.status_code)
            return True
        log.warning(
            "Webhook returned non-success status %s: %s",
            resp.status_code,
            resp.text[:200],
        )
        return False
    except Exception as exc:  # noqa: BLE001
        log.warning("Webhook delivery failed: %s", exc)
        return False
