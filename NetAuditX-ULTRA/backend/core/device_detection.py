"""Device-type detection with caching and fallback."""

from __future__ import annotations

import time
from dataclasses import dataclass
from threading import Lock
from typing import Optional

from backend.utils.logger import get_logger
from backend.utils.parsers import detect_vendor

log = get_logger("netauditx.detect")


@dataclass
class CachedDetection:
    vendor: str
    detected_at: float


# Vendor-specific commands to try first when running scans.
VENDOR_COMMAND_MAP: dict[str, list[str]] = {
    "cisco": ["show version", "show clock", "show running-config | include hostname"],
    "juniper": ["show version", "show system uptime"],
    "arista": ["show version", "show uptime"],
    "mikrotik": ["/system resource print", "/system identity print"],
    "huawei": ["display version", "display clock"],
    "fortinet": ["get system status", "get system performance status"],
    "vyos": ["show version", "show system uptime"],
    "paloalto": ["show system info"],
    "linux": ["uname -a", "uptime", "cat /etc/os-release 2>/dev/null | head -5"],
}

DEFAULT_COMMANDS: list[str] = ["uname -a", "uptime", "show version"]


class DeviceDetector:
    """Best-effort vendor detection from SSH banner / probe output.

    Uses an in-memory cache with a configurable TTL so repeated scans don't
    re-probe the same device on every poll.
    """

    def __init__(self, ttl_seconds: int = 3600) -> None:
        self._cache: dict[str, CachedDetection] = {}
        self._lock = Lock()
        self.ttl = ttl_seconds

    def get_cached(self, host: str) -> Optional[str]:
        with self._lock:
            entry = self._cache.get(host)
            if not entry:
                return None
            if time.time() - entry.detected_at > self.ttl:
                self._cache.pop(host, None)
                return None
            return entry.vendor

    def remember(self, host: str, vendor: str) -> None:
        with self._lock:
            self._cache[host] = CachedDetection(vendor=vendor, detected_at=time.time())
        log.info("Cached vendor for %s: %s", host, vendor)

    def detect_from_banner(self, host: str, banner: str) -> Optional[str]:
        vendor = detect_vendor(banner)
        if vendor:
            self.remember(host, vendor)
        return vendor

    def detect_from_output(
        self, host: str, output_blobs: list[str]
    ) -> Optional[str]:
        for blob in output_blobs:
            vendor = detect_vendor(blob)
            if vendor:
                self.remember(host, vendor)
                return vendor
        return None

    def commands_for(self, vendor: Optional[str]) -> list[str]:
        if vendor and vendor in VENDOR_COMMAND_MAP:
            return list(VENDOR_COMMAND_MAP[vendor])
        return list(DEFAULT_COMMANDS)


# Module-level singleton — safe across threads.
detector = DeviceDetector()
