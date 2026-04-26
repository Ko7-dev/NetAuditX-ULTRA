"""Parsers for vendor command output (uptime, version banners, etc.)."""

from __future__ import annotations

import re
from typing import Optional

# Crude vendor fingerprints — extended via DeviceDetector.
_VENDOR_HINTS: dict[str, list[str]] = {
    "cisco": ["cisco ios", "cisco internetwork", "cisco nx-os", "cisco adaptive"],
    "juniper": ["junos", "juniper networks"],
    "arista": ["arista"],
    "mikrotik": ["mikrotik", "routeros"],
    "huawei": ["huawei", "vrp"],
    "fortinet": ["fortigate", "fortios"],
    "linux": ["linux", "ubuntu", "debian", "centos", "alpine", "darwin"],
    "vyos": ["vyos"],
    "paloalto": ["palo alto", "pan-os"],
}


def detect_vendor(banner: str) -> Optional[str]:
    if not banner:
        return None
    blob = banner.lower()
    for vendor, hints in _VENDOR_HINTS.items():
        if any(h in blob for h in hints):
            return vendor
    return None


_UPTIME_PATTERNS = [
    # "uptime is 5 weeks, 2 days, 3 hours, 14 minutes"
    re.compile(
        r"uptime is\s+(?:(\d+)\s*years?,\s*)?"
        r"(?:(\d+)\s*weeks?,\s*)?"
        r"(?:(\d+)\s*days?,\s*)?"
        r"(?:(\d+)\s*hours?,\s*)?"
        r"(?:(\d+)\s*minutes?)?",
        re.IGNORECASE,
    ),
    # Linux `uptime`: "up 4 days,  2:13"
    re.compile(
        r"up\s+(?:(\d+)\s*days?,\s*)?(\d+):(\d+)", re.IGNORECASE
    ),
    # Linux `uptime` minutes only: "up 14 min"
    re.compile(r"up\s+(\d+)\s*min", re.IGNORECASE),
]


def parse_uptime_seconds(text: str) -> Optional[int]:
    """Best-effort parse of vendor 'show version'/'uptime' output."""
    if not text:
        return None

    # Cisco / Juniper style
    m = _UPTIME_PATTERNS[0].search(text)
    if m and any(m.groups()):
        years, weeks, days, hours, minutes = (int(g) if g else 0 for g in m.groups())
        return (
            years * 365 * 86400
            + weeks * 7 * 86400
            + days * 86400
            + hours * 3600
            + minutes * 60
        )

    # Linux uptime "up X days, H:M"
    m = _UPTIME_PATTERNS[1].search(text)
    if m:
        days = int(m.group(1) or 0)
        hours = int(m.group(2))
        minutes = int(m.group(3))
        return days * 86400 + hours * 3600 + minutes * 60

    # Linux uptime minutes
    m = _UPTIME_PATTERNS[2].search(text)
    if m:
        return int(m.group(1)) * 60

    return None


def humanize_uptime(seconds: Optional[int]) -> str:
    if seconds is None or seconds < 0:
        return "unknown"
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes or not parts:
        parts.append(f"{minutes}m")
    return " ".join(parts)


def sanitize_output(text: str, max_len: int = 8000) -> str:
    """Strip control chars and limit length."""
    if not text:
        return ""
    cleaned = "".join(ch for ch in text if ch == "\n" or ch == "\t" or 32 <= ord(ch) < 127)
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len] + "\n... [truncated]"
    return cleaned.strip()
