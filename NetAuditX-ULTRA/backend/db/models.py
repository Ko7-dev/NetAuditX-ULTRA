"""SQLAlchemy ORM models."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    ip: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    port: Mapped[int] = mapped_column(Integer, default=22)
    username: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    password: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    vendor_hint: Mapped[Optional[str]] = mapped_column(String(60), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    tags: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    # Discovery / inventory metadata
    mac_address: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    last_latency_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    discovered_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    discovery_source: Mapped[Optional[str]] = mapped_column(
        String(40), nullable=True
    )  # arp | tcp-connect | manual
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    scan_results: Mapped[list["ScanResult"]] = relationship(
        back_populates="device",
        cascade="all, delete-orphan",
        order_by="desc(ScanResult.created_at)",
    )
    open_ports: Mapped[list["OpenPort"]] = relationship(
        back_populates="device",
        cascade="all, delete-orphan",
    )


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=True, index=True
    )
    ip: Mapped[str] = mapped_column(String(120), index=True)
    status: Mapped[str] = mapped_column(String(20), index=True)  # success/failed/offline
    vendor: Mapped[Optional[str]] = mapped_column(String(60), nullable=True)
    uptime_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    raw_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )

    device: Mapped[Optional["Device"]] = relationship(back_populates="scan_results")


class OpenPort(Base):
    """Snapshot of a single open port observed on a device during a scan."""

    __tablename__ = "open_ports"
    __table_args__ = (
        UniqueConstraint("snapshot_id", "ip", "port", name="uq_openport_snapshot_ipport"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, index=True
    )
    ip: Mapped[str] = mapped_column(String(120), index=True)
    port: Mapped[int] = mapped_column(Integer, index=True)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    service: Mapped[Optional[str]] = mapped_column(String(60), nullable=True)
    banner: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    severity: Mapped[str] = mapped_column(String(20), default="info")
    snapshot_id: Mapped[str] = mapped_column(String(40), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )

    device: Mapped[Optional["Device"]] = relationship(back_populates="open_ports")


class DriftEvent(Base):
    """A change observed between two consecutive discovery / scan snapshots."""

    __tablename__ = "drift_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(40), index=True)
    # new_device | gone_device | new_port | closed_port | service_changed
    severity: Mapped[str] = mapped_column(String(20), default="warning")
    target: Mapped[str] = mapped_column(String(120), index=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    snapshot_id: Mapped[str] = mapped_column(String(40), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class Insight(Base):
    __tablename__ = "insights"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    summary: Mapped[str] = mapped_column(Text)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    anomalies: Mapped[list] = mapped_column(JSON, default=list)
    recommendations: Mapped[list] = mapped_column(JSON, default=list)
    devices_total: Mapped[int] = mapped_column(Integer, default=0)
    devices_failed: Mapped[int] = mapped_column(Integer, default=0)
    source: Mapped[str] = mapped_column(String(40), default="rule-based")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)  # info/warning/critical
    title: Mapped[str] = mapped_column(String(200))
    message: Mapped[str] = mapped_column(Text)
    target: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)
    fingerprint: Mapped[str] = mapped_column(String(120), index=True)
    delivered_email: Mapped[bool] = mapped_column(Boolean, default=False)
    delivered_webhook: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class SystemLog(Base):
    __tablename__ = "system_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    level: Mapped[str] = mapped_column(String(10), index=True)
    component: Mapped[str] = mapped_column(String(60), index=True)
    message: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class ScheduledJob(Base):
    __tablename__ = "scheduled_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    interval_minutes: Mapped[int] = mapped_column(Integer, default=15)
    targets: Mapped[list] = mapped_column(JSON, default=list)  # list of IPs/hostnames
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    next_run_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
