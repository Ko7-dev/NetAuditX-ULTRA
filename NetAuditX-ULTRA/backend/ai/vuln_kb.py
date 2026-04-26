"""Vulnerability knowledge base.

Maps well-known TCP ports + service-banner patterns to a service identity, a
weighted base risk score (0-100) and a list of CVE-class hints. The analyzer
combines this with banner-string evidence to compute a deterministic per-port
risk score without requiring an external CVE database.

The data here is curated, not exhaustive — it captures the services and CVE
categories that matter for typical enterprise audits (legacy auth services,
exposed admin UIs, weak crypto, end-of-life network gear).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Optional


# ---------------------------------------------------------------------------
# Port → (service, base_risk, default severity, recommendation)
# ---------------------------------------------------------------------------

PORT_DB: dict[int, dict] = {
    21:    {"service": "ftp",         "base_risk": 60, "severity": "warning",
            "reason": "Plaintext credentials and file transfer over the wire."},
    22:    {"service": "ssh",         "base_risk": 15, "severity": "info",
            "reason": "Acceptable when key-based auth and a hardened cipher list are enforced."},
    23:    {"service": "telnet",      "base_risk": 90, "severity": "critical",
            "reason": "Telnet transmits credentials in cleartext — must be disabled in production."},
    25:    {"service": "smtp",        "base_risk": 25, "severity": "info",
            "reason": "Open SMTP relay risk if not authenticated."},
    53:    {"service": "dns",         "base_risk": 20, "severity": "info",
            "reason": "Recursive DNS exposure can amplify reflection attacks."},
    69:    {"service": "tftp",        "base_risk": 70, "severity": "warning",
            "reason": "Unauthenticated UDP file transfer — common config exfil vector."},
    80:    {"service": "http",        "base_risk": 35, "severity": "warning",
            "reason": "Unencrypted HTTP — credentials and session cookies are exposed."},
    110:   {"service": "pop3",        "base_risk": 55, "severity": "warning",
            "reason": "Plaintext mail authentication."},
    111:   {"service": "rpcbind",     "base_risk": 65, "severity": "warning",
            "reason": "Portmapper exposure aids enumeration of NFS / RPC services."},
    135:   {"service": "msrpc",       "base_risk": 70, "severity": "warning",
            "reason": "Windows RPC — historical RCE chain (e.g. CVE-2003-0352)."},
    139:   {"service": "netbios-ssn", "base_risk": 70, "severity": "warning",
            "reason": "Legacy SMB1 enumeration & relay risk."},
    143:   {"service": "imap",        "base_risk": 50, "severity": "warning",
            "reason": "Plaintext IMAP authentication."},
    161:   {"service": "snmp",        "base_risk": 65, "severity": "warning",
            "reason": "SNMPv1/v2c uses cleartext community strings."},
    389:   {"service": "ldap",        "base_risk": 55, "severity": "warning",
            "reason": "Unencrypted LDAP — anonymous bind enumeration."},
    443:   {"service": "https",       "base_risk": 10, "severity": "info",
            "reason": "Verify TLS version, cipher and certificate validity."},
    445:   {"service": "smb",         "base_risk": 75, "severity": "critical",
            "reason": "SMB exposure (EternalBlue / SMBGhost class CVEs)."},
    512:   {"service": "rexec",       "base_risk": 90, "severity": "critical",
            "reason": "Berkeley r-services — cleartext, trust-based, must be removed."},
    513:   {"service": "rlogin",      "base_risk": 90, "severity": "critical",
            "reason": "Berkeley r-services — cleartext, trust-based, must be removed."},
    514:   {"service": "rshell",      "base_risk": 90, "severity": "critical",
            "reason": "Berkeley r-services — cleartext, trust-based, must be removed."},
    873:   {"service": "rsync",       "base_risk": 50, "severity": "warning",
            "reason": "Unauthenticated rsync modules can leak entire filesystems."},
    1433:  {"service": "mssql",       "base_risk": 70, "severity": "warning",
            "reason": "Database engine should not be reachable from untrusted networks."},
    1521:  {"service": "oracle",      "base_risk": 70, "severity": "warning",
            "reason": "Oracle TNS exposure — listener/CVE history."},
    2049:  {"service": "nfs",         "base_risk": 60, "severity": "warning",
            "reason": "NFS export visibility — potential anonymous mount."},
    2375:  {"service": "docker-api",  "base_risk": 95, "severity": "critical",
            "reason": "Unauthenticated Docker daemon — trivial root RCE."},
    2376:  {"service": "docker-tls",  "base_risk": 70, "severity": "warning",
            "reason": "Docker TLS — verify mTLS enforced."},
    3306:  {"service": "mysql",       "base_risk": 65, "severity": "warning",
            "reason": "MySQL exposed publicly — credential brute-force risk."},
    3389:  {"service": "rdp",         "base_risk": 75, "severity": "critical",
            "reason": "RDP exposure (BlueKeep / DejaBlue class CVEs)."},
    4444:  {"service": "metasploit",  "base_risk": 95, "severity": "critical",
            "reason": "Default Metasploit handler port — likely compromise indicator."},
    5432:  {"service": "postgres",    "base_risk": 60, "severity": "warning",
            "reason": "PostgreSQL exposed publicly — auth/CVE risk."},
    5900:  {"service": "vnc",         "base_risk": 80, "severity": "critical",
            "reason": "VNC frequently misconfigured without authentication."},
    5985:  {"service": "winrm-http",  "base_risk": 70, "severity": "warning",
            "reason": "WinRM over HTTP — credentials may be exposed."},
    5986:  {"service": "winrm-https", "base_risk": 35, "severity": "info",
            "reason": "WinRM over HTTPS — verify Kerberos / cert auth."},
    6379:  {"service": "redis",       "base_risk": 80, "severity": "critical",
            "reason": "Redis without auth — RCE via slave-of / module load."},
    8080:  {"service": "http-alt",    "base_risk": 35, "severity": "warning",
            "reason": "Common admin UI port — verify authentication."},
    8443:  {"service": "https-alt",   "base_risk": 20, "severity": "info",
            "reason": "Admin UI over TLS — verify cert and auth."},
    9200:  {"service": "elasticsearch","base_risk": 80, "severity": "critical",
            "reason": "Elasticsearch without auth — historic data leak vector."},
    11211: {"service": "memcached",   "base_risk": 75, "severity": "warning",
            "reason": "Memcached UDP exposure — DDoS amplification."},
    27017: {"service": "mongodb",     "base_risk": 80, "severity": "critical",
            "reason": "MongoDB without auth — historic data leak vector."},
}


# ---------------------------------------------------------------------------
# Banner pattern → (CVE label, extra risk, severity bump)
# ---------------------------------------------------------------------------

BANNER_PATTERNS: list[tuple[re.Pattern, dict]] = [
    (re.compile(r"OpenSSH[_/]([0-7]\.\d+)", re.I), {
        "cve": "Legacy OpenSSH (<=7.x) — multiple known CVEs (CVE-2018-15473 user enum, etc.).",
        "extra_risk": 25, "severity": "critical",
    }),
    (re.compile(r"OpenSSH[_/](6\.[0-6])", re.I), {
        "cve": "OpenSSH 6.x — CVE-2016-0777/0778 client roaming vulnerabilities.",
        "extra_risk": 30, "severity": "critical",
    }),
    (re.compile(r"vsftpd 2\.3\.4", re.I), {
        "cve": "vsftpd 2.3.4 backdoor (CVE-2011-2523) — confirmed RCE.",
        "extra_risk": 60, "severity": "critical",
    }),
    (re.compile(r"Apache[/ ]2\.2\.", re.I), {
        "cve": "Apache 2.2.x — end-of-life since 2017, multiple unpatched CVEs.",
        "extra_risk": 25, "severity": "warning",
    }),
    (re.compile(r"Apache[/ ]2\.4\.(?:[1-4][0-9])", re.I), {
        "cve": "Apache 2.4.x older than 2.4.50 — CVE-2021-41773 path traversal.",
        "extra_risk": 35, "severity": "critical",
    }),
    (re.compile(r"nginx[/ ]1\.(?:[0-9]|1[0-7])\.", re.I), {
        "cve": "nginx <1.18 — historical buffer overflow & resolver CVEs.",
        "extra_risk": 20, "severity": "warning",
    }),
    (re.compile(r"Microsoft-IIS[/ ]([56]\.0)", re.I), {
        "cve": "IIS 5/6 — end-of-life, WebDAV RCE class (CVE-2017-7269).",
        "extra_risk": 50, "severity": "critical",
    }),
    (re.compile(r"Microsoft-IIS[/ ]7\.[05]", re.I), {
        "cve": "IIS 7.0/7.5 — end-of-life, multiple unpatched CVEs.",
        "extra_risk": 25, "severity": "warning",
    }),
    (re.compile(r"ProFTPD 1\.3\.5", re.I), {
        "cve": "ProFTPD 1.3.5 mod_copy — CVE-2015-3306 RCE.",
        "extra_risk": 50, "severity": "critical",
    }),
    (re.compile(r"Cisco[- ]IOS[, ]+(?:11|12)\.", re.I), {
        "cve": "End-of-life Cisco IOS 11/12 — many unpatched CVEs (Smart Install etc.).",
        "extra_risk": 30, "severity": "critical",
    }),
    (re.compile(r"Samba 3\.", re.I), {
        "cve": "Samba 3.x — CVE-2017-7494 SambaCry RCE.",
        "extra_risk": 50, "severity": "critical",
    }),
    (re.compile(r"WordPress 4\.", re.I), {
        "cve": "WordPress 4.x — end-of-life branch with known CVEs.",
        "extra_risk": 25, "severity": "warning",
    }),
    (re.compile(r"PHP[/ ]?5\.", re.I), {
        "cve": "PHP 5.x — end-of-life since 2019.",
        "extra_risk": 25, "severity": "warning",
    }),
    (re.compile(r"Server: Werkzeug", re.I), {
        "cve": "Werkzeug debugger may be exposed (PIN bypass class) — CVE-2023-25577.",
        "extra_risk": 20, "severity": "warning",
    }),
    (re.compile(r"Jenkins", re.I), {
        "cve": "Jenkins exposure — verify CVE-2024-23897 (arbitrary file read) is patched.",
        "extra_risk": 15, "severity": "warning",
    }),
]

DEFAULT_PORT_RISK = 10  # tiny baseline for any unknown open port

SEVERITY_RANK = {"info": 0, "warning": 1, "critical": 2}


@dataclass
class PortFinding:
    ip: str
    port: int
    service: str
    severity: str
    risk_score: int
    banner: str = ""
    reasons: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "port": self.port,
            "service": self.service,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "banner": self.banner,
            "reasons": self.reasons,
            "cves": self.cves,
        }


def _bump_severity(current: str, candidate: str) -> str:
    return candidate if SEVERITY_RANK.get(candidate, 0) > SEVERITY_RANK.get(current, 0) else current


def classify_port(ip: str, port: int, banner: Optional[str] = None) -> PortFinding:
    """Classify a single open port with weighted scoring."""
    info = PORT_DB.get(port)
    if info:
        service = info["service"]
        risk = int(info["base_risk"])
        severity = info["severity"]
        reasons = [info["reason"]]
    else:
        service = "unknown"
        risk = DEFAULT_PORT_RISK
        severity = "info"
        reasons = ["Unrecognized service — verify it should be exposed."]

    cves: list[str] = []
    banner = (banner or "").strip()

    if banner:
        for pattern, meta in BANNER_PATTERNS:
            if pattern.search(banner):
                risk += int(meta["extra_risk"])
                severity = _bump_severity(severity, meta["severity"])
                cves.append(meta["cve"])
                reasons.append(f"Banner match: {meta['cve']}")

    risk = max(0, min(100, risk))
    return PortFinding(
        ip=ip,
        port=port,
        service=service,
        severity=severity,
        risk_score=risk,
        banner=banner[:300],
        reasons=reasons,
        cves=cves,
    )


def classify_ports(ports: Iterable[dict]) -> list[PortFinding]:
    """Classify a batch of `{ip, port, banner}` dicts."""
    findings: list[PortFinding] = []
    for p in ports:
        findings.append(
            classify_port(p["ip"], int(p["port"]), p.get("banner"))
        )
    return findings


# Top-N hot ports we probe during fast subnet sweeps.
TOP_TCP_PORTS: list[int] = sorted(
    {
        22, 23, 25, 53, 80, 110, 111, 123, 135, 139, 143, 161, 389,
        443, 445, 465, 587, 631, 636, 873, 990, 993, 995,
        1433, 1521, 1723, 2049, 2375, 2376,
        3000, 3306, 3389, 4444, 5000, 5432, 5601, 5900, 5985, 5986,
        6379, 6660, 6667, 7000, 7547, 8000, 8008, 8080, 8081, 8088,
        8443, 8888, 9000, 9090, 9200, 9300, 9418, 11211, 27017,
    }
)
