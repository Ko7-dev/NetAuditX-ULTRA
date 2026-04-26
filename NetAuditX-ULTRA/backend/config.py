"""
NetAuditX configuration.

All runtime configuration is loaded from environment variables (with sensible
defaults) so the platform can be deployed in any environment without code
changes.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
LOGS_DIR = PROJECT_ROOT / "logs"
FRONTEND_DIR = PROJECT_ROOT / "frontend"

DATA_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)


class Settings(BaseSettings):
    """Strongly-typed runtime settings."""

    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Server ---
    app_name: str = "NetAuditX ULTRA"
    app_version: str = "1.0.0"
    host: str = Field(default="0.0.0.0")
    port: int = Field(default_factory=lambda: int(os.getenv("PORT", "5000")))
    debug: bool = Field(default=False)

    # --- Database ---
    database_url: str = Field(
        default=f"sqlite:///{DATA_DIR / 'netauditx.db'}",
    )

    # --- SSH scanning ---
    ssh_timeout: int = 8
    ssh_max_concurrency: int = 32
    ssh_default_username: str = Field(default="admin")
    ssh_default_password: str = Field(default="")
    ssh_known_hosts: str | None = None  # None disables host-key checking

    # --- Scheduler ---
    scheduler_enabled: bool = True
    default_scan_interval_minutes: int = 15

    # --- Alerts ---
    alert_failure_threshold: int = 3
    alert_risk_score_threshold: int = 70
    alert_dedup_window_minutes: int = 30

    # --- Email ---
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_use_tls: bool = True
    alert_email_from: str | None = None
    alert_email_to: str | None = None  # comma separated

    # --- Webhook ---
    alert_webhook_url: str | None = None

    # --- Optional OpenAI integration ---
    openai_api_key: str | None = None
    openai_model: str = "gpt-4o-mini"

    # --- Demo seed (creates a few sample devices on first boot) ---
    seed_demo_data: bool = True


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
