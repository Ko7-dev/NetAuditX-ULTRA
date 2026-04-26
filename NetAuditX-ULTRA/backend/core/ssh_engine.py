"""Asynchronous SSH scanning engine.

Uses AsyncSSH for true concurrency. Each scan connects to the target,
runs a small set of vendor-aware probe commands, parses the result and
returns a structured dictionary suitable for storage and AI analysis.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import asdict, dataclass, field
from typing import Iterable, Optional

import asyncssh

from backend.config import get_settings
from backend.core.device_detection import detector
from backend.utils.logger import get_logger
from backend.utils.parsers import (
    detect_vendor,
    humanize_uptime,
    parse_uptime_seconds,
    sanitize_output,
)

log = get_logger("netauditx.ssh")


@dataclass
class ScanTarget:
    ip: str
    port: int = 22
    username: Optional[str] = None
    password: Optional[str] = None
    vendor_hint: Optional[str] = None
    name: Optional[str] = None


@dataclass
class ScanResultDTO:
    ip: str
    status: str  # "success" | "failed" | "offline"
    vendor: Optional[str] = None
    uptime_seconds: Optional[int] = None
    uptime_human: str = "unknown"
    raw_output: str = ""
    error: Optional[str] = None
    duration_ms: int = 0
    name: Optional[str] = None
    commands_run: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _run_commands(
    conn: asyncssh.SSHClientConnection, commands: Iterable[str]
) -> list[tuple[str, str, int]]:
    """Execute commands sequentially, returning (cmd, output, exit_status)."""
    results: list[tuple[str, str, int]] = []
    for cmd in commands:
        try:
            res = await asyncio.wait_for(conn.run(cmd, check=False), timeout=10)
            output = (res.stdout or "") + ("\n" + res.stderr if res.stderr else "")
            results.append((cmd, output, int(res.exit_status or 0)))
        except asyncio.TimeoutError:
            results.append((cmd, "[timeout]", -1))
        except Exception as exc:  # noqa: BLE001 - we want resilience
            results.append((cmd, f"[error: {exc}]", -1))
    return results


async def _scan_one(target: ScanTarget, semaphore: asyncio.Semaphore) -> ScanResultDTO:
    settings = get_settings()
    started = time.perf_counter()

    username = target.username or settings.ssh_default_username
    password = target.password or settings.ssh_default_password or None

    async with semaphore:
        try:
            cached_vendor = detector.get_cached(target.ip) or target.vendor_hint
            commands = detector.commands_for(cached_vendor)

            connect_kwargs = dict(
                host=target.ip,
                port=target.port,
                username=username,
                known_hosts=None,  # deliberately disabled for ad-hoc audits
                client_keys=None,
            )
            if password:
                connect_kwargs["password"] = password

            log.info("SSH connect → %s:%s as %s", target.ip, target.port, username)

            async with asyncio.timeout(settings.ssh_timeout):
                async with asyncssh.connect(**connect_kwargs) as conn:
                    cmd_results = await _run_commands(conn, commands)

            joined_output = "\n".join(
                f"$ {cmd}\n{out}" for cmd, out, _ in cmd_results
            )
            blob = "\n".join(out for _, out, _ in cmd_results)

            vendor = (
                cached_vendor
                or detector.detect_from_output(target.ip, [blob])
                or detect_vendor(joined_output)
            )
            uptime_seconds = parse_uptime_seconds(blob)

            duration_ms = int((time.perf_counter() - started) * 1000)
            return ScanResultDTO(
                ip=target.ip,
                status="success",
                vendor=vendor,
                uptime_seconds=uptime_seconds,
                uptime_human=humanize_uptime(uptime_seconds),
                raw_output=sanitize_output(joined_output),
                duration_ms=duration_ms,
                name=target.name,
                commands_run=[c for c, _, _ in cmd_results],
            )

        except asyncssh.PermissionDenied as exc:
            return _failed(target, started, "auth", f"Authentication failed: {exc}")
        except asyncssh.HostKeyNotVerifiable as exc:
            return _failed(target, started, "failed", f"Host key error: {exc}")
        except (OSError, asyncssh.Error) as exc:
            return _failed(target, started, "offline", f"Network/SSH error: {exc}")
        except asyncio.TimeoutError:
            return _failed(target, started, "offline", "Connection timed out")
        except Exception as exc:  # noqa: BLE001 - never bubble through
            log.exception("Unexpected scan failure for %s", target.ip)
            return _failed(target, started, "failed", f"Unexpected error: {exc}")


def _failed(
    target: ScanTarget, started: float, status: str, message: str
) -> ScanResultDTO:
    duration_ms = int((time.perf_counter() - started) * 1000)
    if status == "auth":
        status = "failed"
    return ScanResultDTO(
        ip=target.ip,
        status=status,
        vendor=target.vendor_hint,
        error=message,
        duration_ms=duration_ms,
        name=target.name,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def scan_targets(targets: list[ScanTarget]) -> list[ScanResultDTO]:
    """Concurrently scan a list of targets and return results."""
    if not targets:
        return []
    settings = get_settings()
    semaphore = asyncio.Semaphore(settings.ssh_max_concurrency)
    log.info(
        "Starting concurrent scan of %d targets (max %d in flight)",
        len(targets),
        settings.ssh_max_concurrency,
    )
    coroutines = [_scan_one(t, semaphore) for t in targets]
    results = await asyncio.gather(*coroutines, return_exceptions=False)
    log.info(
        "Scan complete: success=%d failed/offline=%d",
        sum(1 for r in results if r.status == "success"),
        sum(1 for r in results if r.status != "success"),
    )
    return list(results)
