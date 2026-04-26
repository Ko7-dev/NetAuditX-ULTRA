// Network drift timeline page.
import { api } from "/components/api.js";
import { fmtTime, escapeHtml, severityBadge } from "/components/ui.js";

const KIND_GLYPH = {
  new_device:      "＋",
  gone_device:     "－",
  new_port:        "△",
  closed_port:     "▽",
  service_changed: "≠",
};

const KIND_LABEL = {
  new_device:      "New device",
  gone_device:     "Device gone",
  new_port:        "New open port",
  closed_port:     "Port closed",
  service_changed: "Service changed",
};

export async function renderDrift(host) {
  host.innerHTML = `
    <div class="grid" style="gap:18px;">
      <div id="drift-stats"></div>
      <div class="glass card">
        <div class="row between" style="margin-bottom:8px;">
          <h2 style="margin:0">Drift Timeline</h2>
          <div class="row" style="gap:8px;">
            <select class="select" id="flt-kind">
              <option value="">All kinds</option>
              <option value="new_device">New device</option>
              <option value="gone_device">Device gone</option>
              <option value="new_port">New port</option>
              <option value="closed_port">Closed port</option>
              <option value="service_changed">Service changed</option>
            </select>
            <select class="select" id="flt-sev">
              <option value="">All severities</option>
              <option value="critical">Critical</option>
              <option value="warning">Warning</option>
              <option value="info">Info</option>
            </select>
          </div>
        </div>
        <div id="drift-list"></div>
      </div>
    </div>
  `;

  const [stats, events] = await Promise.all([
    api.driftStats().catch(() => ({ total: 0, by_kind: {}, by_severity: {} })),
    api.listDrift({ limit: 200 }).catch(() => []),
  ]);

  drawStats(host.querySelector("#drift-stats"), stats);
  drawList(host.querySelector("#drift-list"), events);

  const refilter = async () => {
    const kind = host.querySelector("#flt-kind").value;
    const sev = host.querySelector("#flt-sev").value;
    const params = { limit: 200 };
    if (kind) params.kind = kind;
    if (sev) params.severity = sev;
    const list = await api.listDrift(params).catch(() => []);
    drawList(host.querySelector("#drift-list"), list);
  };
  host.querySelector("#flt-kind").addEventListener("change", refilter);
  host.querySelector("#flt-sev").addEventListener("change", refilter);
}

function drawStats(target, stats) {
  const cards = [
    { label: "Total drift events", value: stats.total || 0, klass: "cyan" },
    { label: "Critical", value: stats.by_severity?.critical || 0, klass: "bad" },
    { label: "Warning",  value: stats.by_severity?.warning  || 0, klass: "warn" },
    { label: "New devices", value: stats.by_kind?.new_device || 0, klass: "" },
    { label: "New ports", value: stats.by_kind?.new_port || 0, klass: "" },
  ];
  target.innerHTML = `
    <div class="grid grid-4">
      ${cards
        .map(
          (c) => `<div class="stat glass ${c.klass}">
            <div class="label">${c.label}</div><div class="value">${c.value}</div>
          </div>`,
        )
        .join("")}
    </div>
  `;
}

function drawList(target, events) {
  if (!events.length) {
    target.innerHTML = `<div class="empty">No drift events yet — run two discoveries to see changes.</div>`;
    return;
  }
  target.innerHTML = events.map(eventRow).join("");
}

function eventRow(ev) {
  const glyph = KIND_GLYPH[ev.kind] || "•";
  const label = KIND_LABEL[ev.kind] || ev.kind;
  const det = ev.details || {};
  let detailHtml = "";
  if (ev.kind === "new_port" || ev.kind === "closed_port") {
    detailHtml = `port <b>${escapeHtml(String(det.port || ""))}</b> · service ${escapeHtml(det.service || "?")}`;
    if (det.banner) detailHtml += `<div class="muted small mono" style="margin-top:4px;">${escapeHtml(det.banner)}</div>`;
  } else if (ev.kind === "new_device") {
    detailHtml = `${(det.ports || []).length} open port(s): ${(det.ports || []).slice(0, 12).join(", ")}`;
  } else if (ev.kind === "gone_device") {
    detailHtml = `last seen with ${(det.last_ports || []).length} open port(s)`;
  } else if (ev.kind === "service_changed") {
    detailHtml = `port <b>${det.port}</b> banner changed<br>
      <div class="code-block">- ${escapeHtml(det.banner_before || "")}\n+ ${escapeHtml(det.banner_after || "")}</div>`;
  }

  return `
    <div class="row" style="padding:14px 4px; border-bottom:1px solid var(--border-soft); align-items:flex-start;">
      <div style="width:38px; height:38px; border-radius:10px; display:grid; place-items:center;
                  background:rgba(0,240,255,.08); border:1px solid var(--border); font-family:var(--mono); font-size:18px;">
        ${glyph}
      </div>
      <div style="flex:1;">
        <div class="row between">
          <div>
            <b>${label}</b>
            <span class="muted" style="margin-left:8px;">${escapeHtml(ev.target)}</span>
          </div>
          <div class="row" style="gap:8px;">
            ${severityBadge(ev.severity)}
            <span class="muted small">${fmtTime(ev.created_at)}</span>
          </div>
        </div>
        <div class="muted small" style="margin-top:4px;">${detailHtml}</div>
      </div>
    </div>
  `;
}
