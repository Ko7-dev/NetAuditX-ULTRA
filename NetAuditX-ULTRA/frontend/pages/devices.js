import { api } from "/components/api.js";
import {
  fmtTime,
  loadingSkeleton,
  statusChip,
  emptyState,
  escapeHtml,
  toast,
} from "/components/ui.js";

let _devices = [];
let _filter = "";

export async function renderDevices(view) {
  view.innerHTML = `
    <div class="glass card fade-in">
      <div class="row between" style="margin-bottom:14px;flex-wrap:wrap;gap:10px">
        <div>
          <h2 style="margin-bottom:2px">Managed Devices</h2>
          <div class="muted small">Inventory of all SSH-monitored network devices</div>
        </div>
        <div class="row" style="gap:8px">
          <input id="dev-search" class="search" placeholder="Search by name, IP, vendor, tag…" />
          <button class="btn primary" id="btn-add-device">+ Add Device</button>
        </div>
      </div>
      <div id="devices-table">${loadingSkeleton(5)}</div>
    </div>

    <div class="glass card fade-in" id="add-form" style="margin-top:18px;display:none">
      <h2>Add a device</h2>
      <div class="h-sub">SSH credentials are stored locally in the SQLite database.</div>
      <div class="form-row" style="margin-top:8px">
        <div class="field"><label>Name</label><input id="f-name" placeholder="Core Switch 01" /></div>
        <div class="field"><label>IP / Hostname</label><input id="f-ip" placeholder="10.0.0.1" /></div>
        <div class="field"><label>SSH Port</label><input id="f-port" type="number" value="22" /></div>
        <div class="field"><label>Vendor hint (optional)</label>
          <select id="f-vendor">
            <option value="">auto-detect</option>
            <option>cisco</option><option>juniper</option><option>arista</option>
            <option>mikrotik</option><option>huawei</option><option>fortinet</option>
            <option>linux</option><option>vyos</option><option>paloalto</option>
          </select>
        </div>
        <div class="field"><label>Username</label><input id="f-user" placeholder="admin" /></div>
        <div class="field"><label>Password</label><input id="f-pass" type="password" placeholder="••••••••" /></div>
        <div class="field full"><label>Tags (comma separated)</label><input id="f-tags" placeholder="core,router" /></div>
      </div>
      <div class="row" style="margin-top:14px;gap:8px;justify-content:flex-end">
        <button class="btn ghost" id="btn-cancel">Cancel</button>
        <button class="btn primary" id="btn-save">Save device</button>
      </div>
    </div>
  `;

  document.getElementById("btn-add-device").onclick = () => {
    document.getElementById("add-form").style.display = "block";
  };
  document.getElementById("btn-cancel").onclick = () => {
    document.getElementById("add-form").style.display = "none";
  };
  document.getElementById("btn-save").onclick = saveDevice;
  document.getElementById("dev-search").addEventListener("input", (e) => {
    _filter = e.target.value.trim().toLowerCase();
    drawTable();
  });

  await reload();
}

async function reload() {
  try {
    _devices = await api.listDevices();
  } catch (e) {
    toast(`Failed to load devices: ${e.message}`, "error");
    _devices = [];
  }
  drawTable();
}

function drawTable() {
  const root = document.getElementById("devices-table");
  if (!root) return;
  const list = _devices.filter((d) => {
    if (!_filter) return true;
    const blob = `${d.name} ${d.ip} ${d.vendor_hint || ""} ${d.tags || ""}`.toLowerCase();
    return blob.includes(_filter);
  });
  if (!list.length) {
    root.innerHTML = emptyState("◉", "No devices match. Add one to get started.");
    return;
  }
  root.innerHTML = `<table class="table">
    <thead><tr>
      <th>Name</th><th>IP</th><th>Port</th><th>Vendor</th>
      <th>Status</th><th>Last Seen</th><th>Tags</th><th></th>
    </tr></thead>
    <tbody>
      ${list
        .map(
          (d) => `<tr>
            <td><strong>${escapeHtml(d.name)}</strong></td>
            <td class="code">${escapeHtml(d.ip)}</td>
            <td class="code">${d.port}</td>
            <td>${escapeHtml(d.vendor_hint || "auto")}</td>
            <td>${statusChip(d.last_status || (d.enabled ? "" : "muted"))}</td>
            <td class="muted small">${fmtTime(d.last_seen_at)}</td>
            <td>${(d.tags || "").split(",").filter(Boolean).map(t=>`<span class="chip muted">${escapeHtml(t.trim())}</span>`).join(" ")}</td>
            <td style="text-align:right">
              <button class="btn ghost small" data-act="scan" data-ip="${escapeHtml(d.ip)}">Scan</button>
              <button class="btn ghost small" data-act="del" data-id="${d.id}" style="color:var(--red)">Delete</button>
            </td>
          </tr>`
        )
        .join("")}
    </tbody>
  </table>`;

  root.querySelectorAll('button[data-act="del"]').forEach((b) =>
    b.addEventListener("click", () => deleteDevice(parseInt(b.dataset.id, 10)))
  );
  root.querySelectorAll('button[data-act="scan"]').forEach((b) =>
    b.addEventListener("click", () => scanOne(b.dataset.ip))
  );
}

async function saveDevice() {
  const body = {
    name: document.getElementById("f-name").value.trim(),
    ip: document.getElementById("f-ip").value.trim(),
    port: parseInt(document.getElementById("f-port").value, 10) || 22,
    vendor_hint: document.getElementById("f-vendor").value || null,
    username: document.getElementById("f-user").value.trim() || null,
    password: document.getElementById("f-pass").value || null,
    tags: document.getElementById("f-tags").value.trim() || null,
    enabled: true,
  };
  if (!body.name || !body.ip) {
    toast("Name and IP are required", "error");
    return;
  }
  try {
    await api.createDevice(body);
    toast("Device added", "success");
    document.getElementById("add-form").style.display = "none";
    ["f-name","f-ip","f-user","f-pass","f-tags"].forEach(id => document.getElementById(id).value = "");
    await reload();
  } catch (e) {
    toast(`Failed to add device: ${e.message}`, "error");
  }
}

async function deleteDevice(id) {
  if (!confirm("Delete this device and its scan history?")) return;
  try {
    await api.deleteDevice(id);
    toast("Device deleted", "success");
    await reload();
  } catch (e) {
    toast(`Delete failed: ${e.message}`, "error");
  }
}

async function scanOne(ip) {
  toast(`Scanning ${ip} …`);
  try {
    const res = await api.triggerScan({ targets: [ip] });
    toast(`Scan complete: ${res.success} ok / ${res.failed} failed`, res.failed ? "error" : "success");
    await reload();
  } catch (e) {
    toast(`Scan failed: ${e.message}`, "error");
  }
}
