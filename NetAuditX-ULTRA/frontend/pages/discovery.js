// Subnet discovery page.
import { api } from "/components/api.js";
import { toast, severityBadge } from "/components/ui.js";

export async function renderDiscovery(host) {
  host.innerHTML = `
    <div class="grid" style="gap:18px;">
      <div class="glass card">
        <div class="row between" style="margin-bottom:8px;">
          <h2 style="margin:0">Subnet Discovery</h2>
          <span class="muted small">ARP + TCP-connect sweep · top ~50 ports</span>
        </div>
        <p class="muted small" style="margin-top:0">
          Sweep an entire CIDR (max /20) for live hosts, banner-grab common services and
          score every open port against the vulnerability knowledge base.
        </p>
        <form id="disc-form" class="grid grid-4" style="gap:12px; align-items:end;">
          <div class="field" style="grid-column: span 2;">
            <label>CIDR subnet</label>
            <input class="input" name="cidr" placeholder="10.0.0.0/24" value="10.10.0.0/29" required />
          </div>
          <div class="field">
            <label>Per-port timeout (s)</label>
            <input class="input" name="timeout" type="number" step="0.1" min="0.1" max="5" value="0.6" />
          </div>
          <div class="field">
            <label>Concurrency</label>
            <input class="input" name="max_concurrency" type="number" min="16" max="2000" value="512" />
          </div>
          <div class="field" style="grid-column: span 2;">
            <label>Custom ports (comma-sep, optional)</label>
            <input class="input" name="ports" placeholder="22,80,443,3389" />
          </div>
          <div class="field">
            <label>Try ARP first</label>
            <select class="select" name="use_arp"><option value="true">Yes</option><option value="false">No</option></select>
          </div>
          <div class="field">
            <label>Persist to inventory</label>
            <select class="select" name="persist"><option value="true">Yes</option><option value="false">No</option></select>
          </div>
          <div style="grid-column: 1 / -1;">
            <button class="btn primary" type="submit" id="disc-go">⚡ Run Discovery</button>
          </div>
        </form>
      </div>

      <div id="disc-summary"></div>
      <div id="disc-results" class="glass card" style="display:none;"></div>
    </div>
  `;

  host.querySelector("#disc-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const fd = new FormData(ev.target);
    const portsRaw = (fd.get("ports") || "").trim();
    const ports = portsRaw
      ? portsRaw.split(/[\s,]+/).map((s) => parseInt(s, 10)).filter(Number.isFinite)
      : null;
    const body = {
      cidr: fd.get("cidr").trim(),
      timeout: parseFloat(fd.get("timeout")),
      max_concurrency: parseInt(fd.get("max_concurrency"), 10),
      use_arp: fd.get("use_arp") === "true",
      persist: fd.get("persist") === "true",
      ports,
    };
    const btn = host.querySelector("#disc-go");
    btn.disabled = true;
    const oldText = btn.textContent;
    btn.textContent = "⏳ Sweeping…";
    host.querySelector("#disc-summary").innerHTML =
      `<div class="glass card muted">Running discovery on <b>${body.cidr}</b> — this can take up to 60 seconds for a /24…</div>`;
    try {
      const res = await api.discover(body);
      renderResult(host, res);
      toast(
        `Discovery: ${res.hosts_total} host(s) in ${res.duration_ms}ms via ${res.method}` +
          (res.devices_added ? ` · +${res.devices_added} new device(s)` : "") +
          (res.drift_events ? ` · ${res.drift_events} drift event(s)` : ""),
        "success",
        5000,
      );
    } catch (e) {
      toast(`Discovery failed: ${e.message}`, "error");
      host.querySelector("#disc-summary").innerHTML =
        `<div class="glass card" style="border-color: rgba(255,77,109,.4)"><b>Discovery failed:</b> ${e.message}</div>`;
    } finally {
      btn.disabled = false;
      btn.textContent = oldText;
    }
  });
}

function renderResult(host, res) {
  const summary = host.querySelector("#disc-summary");
  const stats = [
    { label: "Hosts alive", value: res.hosts_total, klass: "cyan" },
    { label: "Method", value: res.method, klass: "" },
    { label: "Duration", value: `${res.duration_ms} ms`, klass: "" },
    { label: "Inventory added", value: res.devices_added, klass: res.devices_added ? "good" : "" },
    { label: "Drift events", value: res.drift_events, klass: res.drift_events ? "warn" : "" },
  ];
  summary.innerHTML = `
    <div class="grid grid-4">
      ${stats
        .map(
          (s) => `
        <div class="stat glass ${s.klass}">
          <div class="label">${s.label}</div>
          <div class="value">${s.value ?? 0}</div>
        </div>`,
        )
        .join("")}
    </div>
  `;

  const wrap = host.querySelector("#disc-results");
  wrap.style.display = "block";

  if (!res.hosts.length) {
    wrap.innerHTML = `<div class="empty">No live hosts found in this subnet.</div>`;
    return;
  }

  wrap.innerHTML = `
    <div class="row between" style="margin-bottom:8px;">
      <h3 style="margin:0">Live hosts</h3>
      <span class="muted small">snapshot ${res.snapshot_id}</span>
    </div>
    <div style="overflow:auto;max-height:62vh;">
      <table class="tbl">
        <thead>
          <tr>
            <th>Host</th><th>MAC</th><th>Latency</th>
            <th>Source</th><th>Risk</th><th>Open ports</th>
          </tr>
        </thead>
        <tbody>
          ${res.hosts.map(hostRow).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function hostRow(h) {
  const ports = (h.open_ports || [])
    .sort((a, b) => b.risk_score - a.risk_score)
    .slice(0, 10)
    .map(
      (p) =>
        `<span class="badge ${p.severity}" title="${escapeAttr(p.banner || p.service)}">
            ${p.port}/${p.service}${p.cves && p.cves.length ? " ⚠" : ""}
         </span>`,
    )
    .join(" ");
  return `
    <tr>
      <td class="mono">
        <div><b>${h.ip}</b></div>
        <div class="muted small">${h.hostname || ""}</div>
      </td>
      <td class="mono">${h.mac || "—"}</td>
      <td>${h.latency_ms != null ? h.latency_ms + " ms" : "—"}</td>
      <td><span class="badge muted">${h.source}</span></td>
      <td>${severityBadge(h.severity, `${h.total_risk}`)}</td>
      <td style="max-width:520px;">${ports || '<span class="muted small">none</span>'}</td>
    </tr>
  `;
}

function escapeAttr(s) {
  return String(s || "").replace(/"/g, "&quot;").replace(/</g, "&lt;");
}
