"""Validators for IPs, hostnames, and credentials."""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)*"
    r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)$"
)


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def is_valid_hostname(value: str) -> bool:
    if not value or len(value) > 253:
        return False
    return bool(_HOSTNAME_RE.match(value))


def is_valid_target(value: str) -> bool:
    return is_valid_ip(value) or is_valid_hostname(value)


def normalize_targets(targets: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in targets:
        if not raw:
            continue
        t = raw.strip()
        if not t or t in seen:
            continue
        seen.add(t)
        out.append(t)
    return out
