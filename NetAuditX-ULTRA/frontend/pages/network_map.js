// Network topology map — pure SVG, no external libs.
// Lays nodes around a central hub via simple polar layout, color by status.
import { api } from "/components/api.js";
import { fmtTime, escapeHtml } from "/components/ui.js";

const STATUS_COLOR = {
  success: "#2ee68b",
  failed:  "#ff4d6d",
  offline: "#ff4d6d",
  unknown: "#7d8fb6",
};

export async function renderNetworkMap(host) {
  host.innerHTML = `
    <div class="grid" style="gap:18px;">
      <div class="glass card">
        <div class="row between">
          <div>
            <h2 style="margin:0">Network Map</h2>
            <div class="muted small">Hub-and-spoke topology coloured by latest scan status. Click a node for details.</div>
          </div>
          <div class="row" style="gap:12px;">
            <div class="muted small" id="nm-counts">—</div>
          </div>
        </div>
      </div>

      <div class="netmap-host" id="nm-host">
        <div class="netmap-tooltip" id="nm-tip"></div>
        <div class="netmap-legend">
          <div><span class="swatch" style="background:#2ee68b"></span>Reachable</div>
          <div><span class="swatch" style="background:#ff4d6d"></span>Failed / Offline</div>
          <div><span class="swatch" style="background:#7d8fb6"></span>Unknown</div>
          <div><span class="swatch" style="background:#00f0ff"></span>Hub (this host)</div>
        </div>
      </div>
    </div>
  `;

  const [devices, results] = await Promise.all([
    api.listDevices().catch(() => []),
    api.listResults({ limit: 500 }).catch(() => []),
  ]);

  // Latest status per IP
  const latest = {};
  for (const r of results) {
    if (!latest[r.ip]) latest[r.ip] = r;
  }

  const nodes = devices.map((d) => {
    const last = latest[d.ip];
    return {
      id: d.id,
      ip: d.ip,
      name: d.name,
      vendor: d.vendor_hint,
      enabled: d.enabled,
      hostname: d.hostname,
      mac: d.mac_address,
      latency_ms: d.last_latency_ms,
      status: last ? last.status : "unknown",
      last_seen: last ? last.created_at : null,
      raw: d,
    };
  });

  drawTopology(host, nodes);
}

function drawTopology(host, nodes) {
  const svgHost = host.querySelector("#nm-host");
  const counts = host.querySelector("#nm-counts");
  const tip = host.querySelector("#nm-tip");

  const ok = nodes.filter((n) => n.status === "success").length;
  const bad = nodes.filter((n) => n.status === "failed" || n.status === "offline").length;
  counts.textContent = `${nodes.length} device(s) · ${ok} reachable · ${bad} failed`;

  const W = svgHost.clientWidth || 900;
  const H = svgHost.clientHeight || 560;
  const cx = W / 2;
  const cy = H / 2;
  const radius = Math.min(W, H) * 0.36;

  if (!nodes.length) {
    svgHost.insertAdjacentHTML(
      "beforeend",
      `<div class="empty" style="position:absolute;inset:0;display:grid;place-items:center;border:none;">
         No devices yet — add some on the Devices page or run a Discovery sweep.
       </div>`,
    );
    return;
  }

  // Polar layout — one ring (or two if many hosts).
  const ring1 = nodes.slice(0, 14);
  const ring2 = nodes.slice(14);

  function place(list, r) {
    return list.map((n, i) => {
      const a = (i / list.length) * Math.PI * 2 - Math.PI / 2;
      return { ...n, x: cx + r * Math.cos(a), y: cy + r * Math.sin(a) };
    });
  }

  const positioned = [
    ...place(ring1, radius),
    ...place(ring2, radius * 0.55),
  ];

  let edges = "";
  let circles = "";
  let labels = "";
  for (const n of positioned) {
    const color = STATUS_COLOR[n.status] || STATUS_COLOR.unknown;
    edges += `<line class="netmap-edge" x1="${cx}" y1="${cy}" x2="${n.x}" y2="${n.y}" />`;
    circles += `
      <g class="netmap-node" data-id="${n.id}" transform="translate(${n.x},${n.y})">
        <circle r="13" fill="${color}" fill-opacity="0.18" stroke="${color}" stroke-width="2"
                style="filter: drop-shadow(0 0 8px ${color}80);"></circle>
        <circle r="4" fill="${color}"></circle>
      </g>
    `;
    labels += `<text class="netmap-label" x="${n.x}" y="${n.y + 26}" text-anchor="middle">${escapeHtml(n.ip)}</text>`;
  }

  // Hub
  const hub = `
    <g>
      <circle cx="${cx}" cy="${cy}" r="26" fill="#00f0ff" fill-opacity="0.18" stroke="#00f0ff" stroke-width="2"
              style="filter: drop-shadow(0 0 14px #00f0ffaa);"></circle>
      <circle cx="${cx}" cy="${cy}" r="9" fill="#00f0ff"></circle>
      <text class="netmap-label" x="${cx}" y="${cy + 42}" text-anchor="middle" style="font-size:11px;fill:#e6f1ff;">NetAuditX Hub</text>
    </g>
  `;

  svgHost.insertAdjacentHTML(
    "beforeend",
    `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet">
       ${edges}${hub}${circles}${labels}
     </svg>`,
  );

  // Tooltip wiring
  svgHost.querySelectorAll(".netmap-node").forEach((g) => {
    const id = parseInt(g.dataset.id, 10);
    const n = positioned.find((x) => x.id === id);
    g.addEventListener("mouseenter", (e) => {
      tip.innerHTML = nodeTooltipHtml(n);
      tip.style.display = "block";
    });
    g.addEventListener("mousemove", (e) => {
      const rect = svgHost.getBoundingClientRect();
      tip.style.left = (e.clientX - rect.left + 14) + "px";
      tip.style.top = (e.clientY - rect.top + 14) + "px";
    });
    g.addEventListener("mouseleave", () => (tip.style.display = "none"));
  });
}

function nodeTooltipHtml(n) {
  return `
    <div><b>${escapeHtml(n.name || n.ip)}</b></div>
    <div class="muted small">${escapeHtml(n.ip)}${n.hostname ? " · " + escapeHtml(n.hostname) : ""}</div>
    <div style="margin-top:6px;">
      <span class="badge ${n.status}">${n.status}</span>
      ${n.vendor ? `<span class="badge muted" style="margin-left:4px;">${escapeHtml(n.vendor)}</span>` : ""}
    </div>
    <div class="muted small" style="margin-top:6px;">
      ${n.mac ? `MAC ${escapeHtml(n.mac)}<br>` : ""}
      ${n.latency_ms != null ? `Latency ${n.latency_ms} ms<br>` : ""}
      Last seen: ${fmtTime(n.last_seen)}
    </div>
  `;
}
