// Main router + bootstrapping for NetAuditX UI.
import { api } from "/components/api.js";
import { toast, fmtTime } from "/components/ui.js";
import { renderDashboard } from "/pages/dashboard.js";
import { renderDevices } from "/pages/devices.js";
import { renderResults } from "/pages/results.js";
import { renderInsights } from "/pages/insights.js";
import { renderAlerts } from "/pages/alerts.js";
import { renderSchedules } from "/pages/schedules.js";
import { renderDiscovery } from "/pages/discovery.js";
import { renderNetworkMap } from "/pages/network_map.js";
import { renderDrift } from "/pages/drift.js";
import { renderLogs } from "/pages/logs.js";

const ROUTES = {
  dashboard:   { title: "Dashboard",     sub: "Real-time network health overview", render: renderDashboard, autoRefresh: true },
  discovery:   { title: "Discovery",     sub: "Subnet sweep — find live hosts and open ports", render: renderDiscovery, autoRefresh: false },
  network_map: { title: "Network Map",   sub: "Topology of every device with live status", render: renderNetworkMap, autoRefresh: true },
  devices:     { title: "Devices",       sub: "Inventory of monitored network devices", render: renderDevices, autoRefresh: true },
  results:     { title: "Scan Results",  sub: "All structured device scan outcomes", render: renderResults, autoRefresh: true },
  insights:    { title: "AI Insights",   sub: "Anomalies, recommendations, and risk score", render: renderInsights, autoRefresh: true },
  drift:       { title: "Network Drift", sub: "Changes detected between successive scans", render: renderDrift, autoRefresh: true },
  alerts:      { title: "Alerts",        sub: "Fired alerts with delivery status", render: renderAlerts, autoRefresh: true },
  schedules:   { title: "Schedules",     sub: "Periodic scan jobs", render: renderSchedules, autoRefresh: false },
  logs:        { title: "Live Logs",     sub: "Streaming SOC console — every backend event in real time", render: renderLogs, autoRefresh: false },
};

const view = document.getElementById("view");
let _autoRefreshTimer = null;
let _currentCleanup = null;

function currentRoute() {
  const hash = (location.hash || "#/dashboard").replace(/^#\//, "");
  return ROUTES[hash] ? hash : "dashboard";
}

function setActive(route) {
  document.querySelectorAll("#nav a").forEach((a) => {
    a.classList.toggle("active", a.dataset.route === route);
  });
  document.getElementById("page-title").textContent = ROUTES[route].title;
  document.getElementById("page-sub").textContent = ROUTES[route].sub;
}

async function navigate() {
  const route = currentRoute();
  setActive(route);
  // Tear down previous page (e.g. close EventSource).
  if (typeof _currentCleanup === "function") {
    try { _currentCleanup(); } catch (_) {}
    _currentCleanup = null;
  }
  view.innerHTML = "";
  try {
    const cleanup = await ROUTES[route].render(view);
    if (typeof cleanup === "function") _currentCleanup = cleanup;
  } catch (e) {
    console.error(e);
    view.innerHTML = `<div class="glass card"><h2 style="color:var(--red)">Page error</h2><div class="muted">${e.message}</div></div>`;
  }
  // Restart auto-refresh if the page wants it.
  if (_autoRefreshTimer) { clearInterval(_autoRefreshTimer); _autoRefreshTimer = null; }
  if (ROUTES[route].autoRefresh) {
    _autoRefreshTimer = setInterval(() => navigate(), 30_000);
  }
}

window.addEventListener("hashchange", navigate);

document.getElementById("btn-refresh").addEventListener("click", () => {
  navigate();
  refreshHealth();
});

document.getElementById("btn-scan-now").addEventListener("click", async () => {
  const btn = document.getElementById("btn-scan-now");
  btn.disabled = true;
  const old = btn.textContent;
  btn.textContent = "⏳ Scanning…";
  try {
    const res = await api.triggerScan({});
    const driftBlurb = res.drift_events ? ` · ${res.drift_events} drift event(s)` : "";
    toast(
      `Scan complete — ${res.success} ok / ${res.failed} failed (risk ${res.insight?.risk_score ?? 0})${driftBlurb}`,
      res.failed ? "error" : "success",
      4500,
    );
    navigate();
  } catch (e) {
    toast(`Scan failed: ${e.message}`, "error");
  } finally {
    btn.disabled = false;
    btn.textContent = old;
  }
});

async function refreshHealth() {
  const label = document.getElementById("health-label");
  const last = document.getElementById("last-refresh");
  try {
    const h = await api.health();
    label.textContent = `${h.app} healthy`;
    label.parentElement.classList.remove("bad");
  } catch (e) {
    label.textContent = "Backend unreachable";
    label.parentElement.classList.add("bad");
  }
  last.textContent = `updated ${fmtTime(new Date().toISOString())}`;
}

// Bootstrap
refreshHealth();
navigate();
setInterval(refreshHealth, 20_000);
