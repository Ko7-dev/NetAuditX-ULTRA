"""AI analysis engine.

Combines three signals into a single risk score (0-100) and a structured
insight payload:

  1. Reachability — how many devices succeeded vs failed in the latest scan.
  2. Behavioural anomalies — flapping, mass failure, repeated auth failures,
     uptime resets (see :mod:`backend.ai.anomaly`).
  3. Port vulnerabilities — predictive scoring driven by the curated
     vulnerability knowledge base in :mod:`backend.ai.vuln_kb`. Each open port
     is classified into a service identity and weighted by base port risk +
     banner-pattern CVE hits, then aggregated per host.

A rule-based engine is the always-on default. If `OPENAI_API_KEY` is set, an
optional refinement pass enriches the executive summary text. Failures fall
back silently to the rule-based output so the analyzer is *always* available.
"""

from __future__ import annotations

import json
from typing import Any, Iterable

import httpx
from sqlalchemy.orm import Session

from backend.ai.anomaly import detect_anomalies
from backend.ai.vuln_kb import classify_ports
from backend.config import get_settings
from backend.utils.logger import get_logger

log = get_logger("netauditx.ai")


_SEVERITY_WEIGHT = {"info": 5, "warning": 15, "critical": 30}


# ---------------------------------------------------------------------------
# Vulnerability findings (predictive port scoring)
# ---------------------------------------------------------------------------


def score_ports(ports: Iterable[dict]) -> dict[str, Any]:
    """Score a flat list of `{ip, port, banner}` dicts.

    Returns a dict with the per-port findings, aggregated severity counts and
    a sub-score (0-100) suitable for blending into the network risk score.
    """
    findings = classify_ports(ports)
    by_severity = {"info": 0, "warning": 0, "critical": 0}
    risks: list[int] = []
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        risks.append(f.risk_score)

    if not findings:
        sub_score = 0
    else:
        # Weighted aggregate: 70% top-port risk + 30% mean of top-10 risks.
        risks_sorted = sorted(risks, reverse=True)
        top = risks_sorted[0]
        topn = risks_sorted[: min(10, len(risks_sorted))]
        mean_topn = sum(topn) / len(topn)
        sub_score = int(round(0.7 * top + 0.3 * mean_topn))

    return {
        "score": max(0, min(100, sub_score)),
        "by_severity": by_severity,
        "findings": [f.to_dict() for f in findings],
    }


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------


def _score(
    results: list[dict],
    anomalies: list[dict],
    port_score: int,
) -> int:
    if not results and port_score == 0:
        return 0

    score = 0
    if results:
        total = len(results)
        failed = sum(1 for r in results if r.get("status") != "success")
        failure_ratio = failed / total
        score += int(failure_ratio * 50)

        fresh_reboots = sum(
            1
            for r in results
            if r.get("status") == "success"
            and r.get("uptime_seconds") is not None
            and r["uptime_seconds"] < 600
        )
        score += min(15, fresh_reboots * 5)

    for a in anomalies:
        score += _SEVERITY_WEIGHT.get(a.get("severity", "info"), 5)

    # Port-vulnerability sub-score is folded in proportionally so large open
    # surfaces meaningfully raise the network risk even when devices are
    # all "reachable".
    score += int(port_score * 0.4)

    return max(0, min(100, score))


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------


def _recommendations(
    results: list[dict],
    anomalies: list[dict],
    port_findings: list[dict],
    risk_score: int,
) -> list[str]:
    recs: list[str] = []

    failed = [r for r in results if r.get("status") != "success"]
    if failed:
        sample = ", ".join(r["ip"] for r in failed[:5])
        more = "" if len(failed) <= 5 else f" (+{len(failed) - 5} more)"
        recs.append(
            f"Investigate {len(failed)} unreachable device(s): {sample}{more}."
        )

    auth_anoms = [a for a in anomalies if a["type"] == "repeated_auth_failure"]
    if auth_anoms:
        recs.append(
            "Rotate SSH credentials and verify the audit account is not locked "
            "out on affected devices."
        )

    flap_anoms = [a for a in anomalies if a["type"] == "flapping_device"]
    if flap_anoms:
        recs.append(
            "Inspect uplinks/power for flapping devices; correlate with "
            "switchport error counters."
        )

    reboot_anoms = [a for a in anomalies if a["type"] == "uptime_reset"]
    if reboot_anoms:
        recs.append(
            "Confirm whether recent reboots were planned. Pull crash/syslog "
            "from affected devices."
        )

    if any(a["type"] == "mass_failure" for a in anomalies):
        recs.append(
            "Treat as a possible network-wide outage: validate management "
            "VLAN, jump host and DNS resolution before further scans."
        )

    # Port-vulnerability driven recs.
    crits = [f for f in port_findings if f.get("severity") == "critical"]
    if crits:
        sample = ", ".join(f"{f['ip']}:{f['port']}" for f in crits[:5])
        more = "" if len(crits) <= 5 else f" (+{len(crits) - 5} more)"
        recs.append(
            f"Close or harden {len(crits)} critical-risk port(s) immediately: {sample}{more}."
        )
    legacy_telnet = [f for f in port_findings if f.get("service") == "telnet"]
    if legacy_telnet:
        recs.append(
            "Disable Telnet on every device that exposes it — replace with SSH key auth."
        )
    if any(f.get("service") in {"docker-api", "redis", "elasticsearch", "mongodb"} and f.get("severity") == "critical" for f in port_findings):
        recs.append(
            "Lock down unauthenticated data services (Docker / Redis / Elasticsearch / MongoDB) "
            "behind firewall ACLs and require authentication."
        )

    if risk_score >= 70 and not recs:
        recs.append(
            "Multiple low-severity issues are compounding into elevated risk — "
            "perform a manual review of recent change tickets."
        )

    if not recs:
        recs.append("All monitored devices are healthy. Continue normal monitoring.")

    return recs


# ---------------------------------------------------------------------------
# Summary text
# ---------------------------------------------------------------------------


def _summary(
    results: list[dict],
    anomalies: list[dict],
    port_findings: list[dict],
    risk_score: int,
) -> str:
    total = len(results)
    if total == 0 and not port_findings:
        return "No scan data available yet. Trigger a scan to populate insights."

    success = sum(1 for r in results if r.get("status") == "success")
    failed = total - success
    vendor_counts: dict[str, int] = {}
    for r in results:
        v = r.get("vendor")
        if v:
            vendor_counts[v] = vendor_counts.get(v, 0) + 1
    vendors_blob = ", ".join(f"{v}×{c}" for v, c in vendor_counts.items()) or "unknown"

    health = (
        "healthy" if risk_score < 30
        else "degraded" if risk_score < 70
        else "at risk"
    )
    parts = [f"Network status: {health.upper()} (risk score {risk_score}/100)."]
    if total:
        parts.append(f"{success}/{total} devices reachable; {failed} failed/offline.")
        parts.append(f"Vendors observed: {vendors_blob}.")
    if anomalies:
        crit = sum(1 for a in anomalies if a["severity"] == "critical")
        warn = sum(1 for a in anomalies if a["severity"] == "warning")
        parts.append(f"Detected {len(anomalies)} anomaly(ies) — {crit} critical, {warn} warning.")
    if port_findings:
        crit = sum(1 for f in port_findings if f["severity"] == "critical")
        warn = sum(1 for f in port_findings if f["severity"] == "warning")
        parts.append(
            f"Port surface: {len(port_findings)} open port(s) — {crit} critical, {warn} warning."
        )
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Optional OpenAI refinement
# ---------------------------------------------------------------------------


def _try_openai_refine(payload: dict[str, Any]) -> dict[str, Any] | None:
    settings = get_settings()
    if not settings.openai_api_key:
        return None

    prompt = (
        "You are a senior network operations analyst. Given the JSON below, "
        "rewrite the 'summary' field as one short, executive-friendly paragraph "
        "and return the same JSON shape. Do not change risk_score or anomalies."
        "\n\nINPUT:\n" + json.dumps(payload)
    )
    try:
        resp = httpx.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {settings.openai_api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": settings.openai_model,
                "messages": [
                    {"role": "system", "content": "Reply with valid JSON only."},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.2,
                "response_format": {"type": "json_object"},
            },
            timeout=20,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        refined = json.loads(content)
        if "summary" in refined and isinstance(refined["summary"], str):
            payload["summary"] = refined["summary"]
            payload["source"] = "openai"
        return payload
    except Exception as exc:  # noqa: BLE001
        log.warning("OpenAI refinement failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def analyze(
    session: Session,
    results: Iterable[dict],
    open_ports: Iterable[dict] | None = None,
) -> dict[str, Any]:
    """Run the full analysis pipeline and return a structured insight dict.

    Parameters
    ----------
    session
        Active SQLAlchemy session (used by the anomaly engine for history).
    results
        Latest SSH scan result dicts (see ``ScanResultDTO.to_dict``).
    open_ports
        Optional list of `{ip, port, banner}` dicts coming from a discovery
        run. When provided, port-vulnerability scoring is folded in.
    """
    results_list = [dict(r) for r in results]
    port_signal = score_ports(open_ports or [])

    anomalies = detect_anomalies(session, results_list)
    risk_score = _score(results_list, anomalies, port_signal["score"])
    summary = _summary(results_list, anomalies, port_signal["findings"], risk_score)
    recommendations = _recommendations(
        results_list, anomalies, port_signal["findings"], risk_score
    )

    payload: dict[str, Any] = {
        "summary": summary,
        "risk_score": risk_score,
        "anomalies": anomalies,
        "recommendations": recommendations,
        "devices_total": len(results_list),
        "devices_failed": sum(
            1 for r in results_list if r.get("status") != "success"
        ),
        "port_findings": port_signal["findings"],
        "port_severity_counts": port_signal["by_severity"],
        "source": "rule-based",
    }

    refined = _try_openai_refine(payload.copy())
    if refined:
        payload = refined
    return payload
