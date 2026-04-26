"""Pydantic request/response models for the API."""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

from backend.utils.validators import is_valid_target


# ---------- Devices ----------


class DeviceCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    ip: str = Field(..., min_length=1, max_length=120)
    port: int = Field(default=22, ge=1, le=65535)
    username: Optional[str] = None
    password: Optional[str] = None
    vendor_hint: Optional[str] = None
    enabled: bool = True
    tags: Optional[str] = None

    @field_validator("ip")
    @classmethod
    def _validate_ip(cls, v: str) -> str:
        if not is_valid_target(v):
            raise ValueError(f"Invalid IP/hostname: {v}")
        return v


class DeviceUpdate(BaseModel):
    name: Optional[str] = None
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    username: Optional[str] = None
    password: Optional[str] = None
    vendor_hint: Optional[str] = None
    enabled: Optional[bool] = None
    tags: Optional[str] = None


class DeviceOut(BaseModel):
    id: int
    name: str
    ip: str
    port: int
    username: Optional[str] = None
    vendor_hint: Optional[str] = None
    enabled: bool
    tags: Optional[str] = None
    last_status: Optional[str] = None
    last_seen_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    last_latency_ms: Optional[float] = None
    discovered_at: Optional[datetime] = None
    discovery_source: Optional[str] = None


# ---------- Scans ----------


class ScanRequest(BaseModel):
    targets: Optional[list[str]] = Field(
        default=None,
        description="Optional list of IPs/hostnames. If omitted, all enabled devices are scanned.",
    )
    username: Optional[str] = None
    password: Optional[str] = None
    port: int = 22

    @field_validator("targets")
    @classmethod
    def _validate_targets(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        if not v:
            return v
        for t in v:
            if not is_valid_target(t):
                raise ValueError(f"Invalid target: {t}")
        return v


class ScanResultOut(BaseModel):
    id: int
    device_id: Optional[int]
    ip: str
    status: str
    vendor: Optional[str] = None
    uptime_seconds: Optional[int] = None
    raw_output: Optional[str] = None
    error: Optional[str] = None
    duration_ms: Optional[int] = None
    created_at: datetime


class ScanResponse(BaseModel):
    scanned: int
    success: int
    failed: int
    results: list[dict[str, Any]]
    insight: dict[str, Any]
    alerts_emitted: int
    drift_events: int = 0


# ---------- Insights ----------


class InsightOut(BaseModel):
    id: int
    summary: str
    risk_score: int
    anomalies: list[dict[str, Any]]
    recommendations: list[str]
    devices_total: int
    devices_failed: int
    source: str
    created_at: datetime


# ---------- Alerts ----------


class AlertOut(BaseModel):
    id: int
    severity: str
    title: str
    message: str
    target: Optional[str] = None
    fingerprint: str
    delivered_email: bool
    delivered_webhook: bool
    created_at: datetime


# ---------- Scheduler ----------


class ScheduleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    interval_minutes: int = Field(default=15, ge=1, le=1440)
    targets: list[str] = Field(default_factory=list)


class ScheduleOut(BaseModel):
    id: int
    name: str
    interval_minutes: int
    targets: list[str]
    enabled: bool
    last_run_at: Optional[datetime] = None


# ---------- Stats / dashboard ----------


class DashboardStats(BaseModel):
    devices_total: int
    devices_enabled: int
    devices_online: int
    devices_offline: int
    scans_24h: int
    failures_24h: int
    risk_score: int
    last_scan_at: Optional[datetime] = None
    open_alerts_24h: int
    vendors: dict[str, int]


# ---------- Discovery ----------


class DiscoveryRequest(BaseModel):
    cidr: str = Field(..., description="CIDR subnet (e.g. 192.168.1.0/24, max /20)")
    ports: Optional[list[int]] = Field(
        default=None,
        description="Optional explicit port list. If omitted, the curated top-ports list is used.",
    )
    timeout: float = Field(default=0.6, ge=0.1, le=5.0)
    max_concurrency: int = Field(default=512, ge=16, le=2000)
    use_arp: bool = True
    persist: bool = Field(
        default=True,
        description="Persist newly discovered devices to inventory (default true).",
    )

    @field_validator("cidr")
    @classmethod
    def _validate_cidr(cls, v: str) -> str:
        try:
            ipaddress.ip_network(v, strict=False)
        except Exception as exc:
            raise ValueError(f"Invalid CIDR: {exc}") from exc
        return v


class DiscoveryHostOut(BaseModel):
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    latency_ms: Optional[float] = None
    source: str
    total_risk: int
    severity: str
    open_ports: list[dict[str, Any]]


class DiscoveryResponse(BaseModel):
    cidr: str
    method: str
    duration_ms: int
    hosts_total: int
    hosts: list[DiscoveryHostOut]
    drift_events: int
    snapshot_id: str
    devices_added: int


# ---------- Drift ----------


class DriftEventOut(BaseModel):
    id: int
    kind: str
    severity: str
    target: str
    details: dict[str, Any]
    snapshot_id: str
    created_at: datetime
