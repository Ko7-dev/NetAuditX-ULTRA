"""Network discovery engine.

Discovers live hosts on a CIDR subnet using two complementary strategies:

1. **Scapy ARP** — when raw sockets are available (`CAP_NET_RAW`), broadcasts an
   ARP-request to the entire subnet, capturing MAC addresses of every replier
   in a single second. Falls back automatically when Scapy is missing or the
   socket cannot be opened.
2. **Async TCP-connect sweep** — for every host in the CIDR, opens a high-fan-out
   batch of TCP connections on the top hot ports. Hosts that accept *any*
   connection are considered alive, the connection latency is recorded and the
   first 256 bytes of the banner are captured. Reverse-DNS is resolved
   in parallel.

The combined result is a list of `DiscoveredHost` records carrying the IP, MAC
(if known), hostname, latency, discovery source and the open ports observed.
This works inside containers and CI environments that do not grant raw-socket
access — making the whole platform portable.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from dataclasses import dataclass, field
from typing import Iterable, Optional

from backend.ai.vuln_kb import TOP_TCP_PORTS, classify_port
from backend.utils.logger import get_logger

log = get_logger("netauditx.discovery")


# Optional Scapy import — wrapped because CAP_NET_RAW is not always available.
try:  # pragma: no cover - import sensitivity
    from scapy.all import ARP, Ether, conf as _scapy_conf, srp  # type: ignore

    _SCAPY_AVAILABLE = True
except Exception as exc:  # noqa: BLE001
    log.info("Scapy unavailable (%s) — discovery will use TCP-connect only.", exc)
    _SCAPY_AVAILABLE = False


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class DiscoveredPort:
    port: int
    service: str
    severity: str
    risk_score: int
    banner: str = ""
    cves: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "service": self.service,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "banner": self.banner,
            "cves": self.cves,
            "reasons": self.reasons,
        }


@dataclass
class DiscoveredHost:
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    latency_ms: Optional[float] = None
    source: str = "tcp-connect"  # arp | tcp-connect | both
    open_ports: list[DiscoveredPort] = field(default_factory=list)

    @property
    def total_risk(self) -> int:
        if not self.open_ports:
            return 0
        # Aggregate: max single-port risk + light bonus for multiple high-risk ports.
        top = max(p.risk_score for p in self.open_ports)
        extras = sum(1 for p in self.open_ports if p.risk_score >= 60) - 1
        return min(100, top + max(0, extras) * 4)

    @property
    def severity(self) -> str:
        if any(p.severity == "critical" for p in self.open_ports):
            return "critical"
        if any(p.severity == "warning" for p in self.open_ports):
            return "warning"
        return "info"

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "latency_ms": self.latency_ms,
            "source": self.source,
            "total_risk": self.total_risk,
            "severity": self.severity,
            "open_ports": [p.to_dict() for p in self.open_ports],
        }


@dataclass
class DiscoveryReport:
    cidr: str
    started_at: float
    duration_ms: int
    hosts_total: int
    method: str  # arp+tcp | tcp-only | arp-only
    hosts: list[DiscoveredHost]

    def to_dict(self) -> dict:
        return {
            "cidr": self.cidr,
            "started_at": self.started_at,
            "duration_ms": self.duration_ms,
            "hosts_total": self.hosts_total,
            "method": self.method,
            "hosts": [h.to_dict() for h in self.hosts],
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _expand(cidr: str) -> list[str]:
    """Return a list of hosts in a CIDR (max 4096 to stay safe)."""
    net = ipaddress.ip_network(cidr, strict=False)
    if net.num_addresses > 4096:
        raise ValueError("Refusing to expand CIDR larger than /20 (4096 hosts).")
    if net.num_addresses == 1:
        return [str(net.network_address)]
    return [str(h) for h in net.hosts()]


def _arp_scan(cidr: str, timeout: float = 1.5) -> dict[str, str]:
    """Broadcast ARP and return {ip: mac}. Empty dict if unavailable."""
    if not _SCAPY_AVAILABLE:
        return {}
    try:  # pragma: no cover - requires raw sockets
        _scapy_conf.verb = 0
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
            timeout=timeout,
            verbose=False,
        )
        return {rcv.psrc: rcv.hwsrc for _snt, rcv in ans}
    except PermissionError:
        log.info("ARP scan needs raw sockets (CAP_NET_RAW); falling back.")
        return {}
    except Exception as exc:  # noqa: BLE001
        log.warning("ARP scan failed (%s); falling back to TCP sweep.", exc)
        return {}


async def _grab_banner(reader: asyncio.StreamReader) -> str:
    try:
        data = await asyncio.wait_for(reader.read(256), timeout=1.0)
        return data.decode("utf-8", errors="replace").strip()
    except (asyncio.TimeoutError, Exception):
        return ""


async def _probe_port(
    ip: str, port: int, timeout: float, sem: asyncio.Semaphore
) -> Optional[tuple[int, str, float]]:
    async with sem:
        started = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
        except (asyncio.TimeoutError, OSError):
            return None
        latency_ms = (time.perf_counter() - started) * 1000
        try:
            # Send a short synthetic prompt for HTTP-like services to elicit a
            # banner (most plain text protocols send banners on connect anyway).
            try:
                if port in {80, 8080, 8000, 8888, 5000, 9090, 3000}:
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                    try:
                        await writer.drain()
                    except Exception:
                        pass
                banner = await _grab_banner(reader)
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
        except Exception:
            banner = ""
        return port, banner, latency_ms


async def _resolve_hostname(ip: str) -> Optional[str]:
    loop = asyncio.get_running_loop()
    try:
        host, *_ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return host
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def discover_subnet(
    cidr: str,
    *,
    ports: Optional[Iterable[int]] = None,
    timeout: float = 0.6,
    max_concurrency: int = 512,
    use_arp: bool = True,
) -> DiscoveryReport:
    """Discover live hosts and their open ports in a CIDR subnet.

    The combined operation is bounded by `max_concurrency` outstanding TCP
    connections, which makes a /24 sweep on the top ~50 ports complete well
    within the 60s SLA on commodity hardware.
    """
    started = time.perf_counter()
    started_ts = time.time()

    target_ports = list(ports) if ports else TOP_TCP_PORTS
    hosts = _expand(cidr)
    log.info(
        "Discovery start: cidr=%s hosts=%d ports=%d concurrency=%d",
        cidr,
        len(hosts),
        len(target_ports),
        max_concurrency,
    )

    arp_table: dict[str, str] = {}
    if use_arp:
        arp_table = await asyncio.get_running_loop().run_in_executor(
            None, _arp_scan, cidr
        )

    sem = asyncio.Semaphore(max_concurrency)

    async def _scan_host(ip: str) -> Optional[DiscoveredHost]:
        probes = [_probe_port(ip, p, timeout, sem) for p in target_ports]
        results = [r for r in await asyncio.gather(*probes) if r]

        if not results and ip not in arp_table:
            return None  # truly silent host

        latencies = [lat for _, _, lat in results]
        latency_ms = round(sum(latencies) / len(latencies), 2) if latencies else None

        open_ports: list[DiscoveredPort] = []
        for port, banner, _ in results:
            finding = classify_port(ip, port, banner)
            open_ports.append(
                DiscoveredPort(
                    port=finding.port,
                    service=finding.service,
                    severity=finding.severity,
                    risk_score=finding.risk_score,
                    banner=finding.banner,
                    cves=finding.cves,
                    reasons=finding.reasons,
                )
            )

        hostname = await _resolve_hostname(ip)

        if ip in arp_table and results:
            source = "arp+tcp"
        elif ip in arp_table:
            source = "arp"
        else:
            source = "tcp-connect"

        return DiscoveredHost(
            ip=ip,
            mac=arp_table.get(ip),
            hostname=hostname,
            latency_ms=latency_ms,
            source=source,
            open_ports=open_ports,
        )

    tasks = [_scan_host(ip) for ip in hosts]
    raw = await asyncio.gather(*tasks)
    discovered = [h for h in raw if h is not None]
    discovered.sort(key=lambda h: tuple(int(o) for o in h.ip.split(".")) if "." in h.ip else (h.ip,))

    duration_ms = int((time.perf_counter() - started) * 1000)
    method = (
        "arp+tcp" if arp_table else "tcp-only"
    )
    log.info(
        "Discovery complete: cidr=%s alive=%d/%d in %dms (method=%s)",
        cidr,
        len(discovered),
        len(hosts),
        duration_ms,
        method,
    )
    return DiscoveryReport(
        cidr=cidr,
        started_at=started_ts,
        duration_ms=duration_ms,
        hosts_total=len(discovered),
        method=method,
        hosts=discovered,
    )
