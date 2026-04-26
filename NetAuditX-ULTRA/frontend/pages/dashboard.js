import { api } from "/components/api.js";
import {
  fmtTime,
  loadingSkeleton,
  severityChip,
  statusChip,
  emptyState,
  escapeHtml,
} from "/components/ui.js";

function ringColor(score) {
  if (score >= 70) return "var(--red)";
  if (score >= 30) return "var(--amber)";
  return "var(--green)";
}

export async function renderDashboard(view) {
  view.innerHTML = `
    <div class="grid cols-4">
      ${[1,2,3,4].map(()=>`<div class="glass stat"><div class="skeleton" style="height:64px"></div></div>`).join("")}
    </div>
    <div class="grid cols-2" style="margin-top:16px">
      <div class="glass card"><div class="skeleton" style="height:180px"></div></div>
      <div class="glass card"><div class="skeleton" style="height:180px"></div></div>
    </div>
  `;

  const [stats, insight, results, alerts] = await Promise.all([
    api.stats().catch(() => null),
    api.latestInsight().catch(() => null),
    api.listResults({ limit: 8 }).catch(() => []),
    api.listAlerts({ limit: 6 }).catch(() => []),
  ]);

  const score = insight?.risk_score ?? 0;

  view.innerHTML = `
    <div class="grid cols-4 fade-in">
      <div class="glass stat">
        <div class="accent-bar"></div>
        <div class="label">Total Devices</div>
        <div class="value">${stats?.devices_total ?? 0}</div>
        <div class="sub">${stats?.devices_enabled ?? 0} enabled</div>
      </div>
      <div class="glass stat">
        <div class="accent-bar" style="background:linear-gradient(135deg,#38e1a4,#4ad6ff)"></div>
        <div class="label">Online</div>
        <div class="value" style="color:var(--green)">${stats?.devices_online ?? 0}</div>
        <div class="sub">last known status</div>
      </div>
      <div class="glass stat">
        <div class="accent-bar" style="background:linear-gradient(135deg,#ff5c7a,#ffbf47)"></div>
        <div class="label">Failures (24h)</div>
        <div class="value" style="color:var(--red)">${stats?.failures_24h ?? 0}</div>
        <div class="sub">${stats?.scans_24h ?? 0} scans</div>
      </div>
      <div class="glass stat">
        <div class="accent-bar" style="background:linear-gradient(135deg,#ffbf47,#ff5c7a)"></div>
        <div class="label">Open Alerts (24h)</div>
        <div class="value" style="color:var(--amber)">${stats?.open_alerts_24h ?? 0}</div>
        <div class="sub">last scan ${fmtTime(stats?.last_scan_at)}</div>
      </div>
    </div>

    <div class="grid cols-2 fade-in" style="margin-top:18px">
      <div class="glass card">
        <h2>Network Risk Score</h2>
        <div class="h-sub">AI-derived health summary across the fleet</div>
        <div class="gauge">
          <div class="gauge-ring" style="--p:${score};--ring-color:${ringColor(score)}">
            <div class="num" style="color:${ringColor(score)}">${score}</div>
            <div class="lbl">/ 100</div>
          </div>
          <div class="gauge-meta">
            <div class="h">Summary</div>
            <div class="t" style="font-size:14px;line-height:1.55;font-weight:500;color:var(--text)">
              ${escapeHtml(insight?.summary || "No insight data yet — trigger a scan to populate.")}
            </div>
            <div class="row" style="margin-top:6px;flex-wrap:wrap;gap:6px">
              <span class="chip muted">${insight?.devices_total ?? 0} devices analyzed</span>
              <span class="chip muted">${(insight?.anomalies || []).length} anomalies</span>
              <span class="chip muted">source: ${escapeHtml(insight?.source || "rule-based")}</span>
            </div>
          </div>
        </div>
      </div>

      <div class="glass card">
        <h2>Vendor Footprint</h2>
        <div class="h-sub">Detected vendors in the last 24 hours</div>
        ${renderVendorBars(stats?.vendors || {})}
      </div>
    </div>

    <div class="grid cols-2 fade-in" style="margin-top:18px">
      <div class="glass card">
        <h2>Recent Scan Results</h2>
        <div class="h-sub">Latest activity across the fleet</div>
        ${renderResultsTable(results)}
      </div>
      <div class="glass card">
        <h2>Recent Alerts</h2>
        <div class="h-sub">Most recent fired alerts</div>
        ${renderAlertsList(alerts)}
      </div>
    </div>
  `;
}

function renderVendorBars(vendors) {
  const entries = Object.entries(vendors);
  if (!entries.length) return emptyState("◌", "No vendor data yet");
  const max = Math.max(...entries.map((e) => e[1]));
  return `<div style="display:flex;flex-direction:column;gap:10px;margin-top:8px">
    ${entries
      .map(([v, c]) => {
        const w = Math.round((c / max) * 100);
        return `<div>
          <div class="row between" style="font-size:12px;margin-bottom:4px">
            <span style="font-weight:600">${escapeHtml(v)}</span>
            <span class="muted">${c}</span>
          </div>
          <div style="height:8px;background:rgba(255,255,255,0.06);border-radius:99px;overflow:hidden">
            <div style="width:${w}%;height:100%;background:var(--accent-grad);border-radius:99px"></div>
          </div>
        </div>`;
      })
      .join("")}
  </div>`;
}

function renderResultsTable(results) {
  if (!results?.length) return emptyState("≣", "No scans yet");
  return `<table class="table">
    <thead><tr><th>IP</th><th>Status</th><th>Vendor</th><th>When</th></tr></thead>
    <tbody>
      ${results
        .map(
          (r) => `<tr>
            <td class="code">${escapeHtml(r.ip)}</td>
            <td>${statusChip(r.status)}</td>
            <td>${escapeHtml(r.vendor || "—")}</td>
            <td class="muted small">${fmtTime(r.created_at)}</td>
          </tr>`
        )
        .join("")}
    </tbody>
  </table>`;
}

function renderAlertsList(alerts) {
  if (!alerts?.length) return emptyState("✓", "No alerts in recent history");
  return `<div style="display:flex;flex-direction:column;gap:10px">
    ${alerts
      .map(
        (a) => `<div class="anomaly">
          <div class="ico ${a.severity}">!</div>
          <div>
            <div style="font-weight:600">${escapeHtml(a.title)}</div>
            <div class="muted small">${escapeHtml(a.message).slice(0,160)}</div>
          </div>
          <div style="text-align:right">
            ${severityChip(a.severity)}
            <div class="muted small" style="margin-top:4px">${fmtTime(a.created_at)}</div>
          </div>
        </div>`
      )
      .join("")}
  </div>`;
}
