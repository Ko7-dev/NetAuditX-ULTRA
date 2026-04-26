"""Centralized logging configuration (file + console + log bus)."""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from backend.config import LOGS_DIR
from backend.utils.log_bus import BusHandler


_LOG_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)-22s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_configured = False


def configure_logging(level: int = logging.INFO) -> None:
    """Configure root logger once. Idempotent."""
    global _configured
    if _configured:
        return

    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    console.setLevel(level)

    log_file: Path = LOGS_DIR / "netauditx.log"
    file_handler = RotatingFileHandler(
        log_file, maxBytes=2_000_000, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)

    bus_handler = BusHandler()
    bus_handler.setFormatter(formatter)
    bus_handler.setLevel(level)

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)
    root.addHandler(console)
    root.addHandler(file_handler)
    root.addHandler(bus_handler)

    # Tame noisy libraries.
    for noisy in ("asyncssh", "apscheduler", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    configure_logging()
    return logging.getLogger(name)
