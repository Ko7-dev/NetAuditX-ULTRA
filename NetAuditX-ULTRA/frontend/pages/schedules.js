import { api } from "/components/api.js";
import {
  fmtTime,
  loadingSkeleton,
  emptyState,
  escapeHtml,
  toast,
} from "/components/ui.js";

let _schedules = [];

export async function renderSchedules(view) {
  view.innerHTML = `
    <div class="grid cols-2 fade-in" style="grid-template-columns:1.2fr 1fr">
      <div class="glass card">
        <div class="row between" style="margin-bottom:12px">
          <div>
            <h2>Scheduled Scans</h2>
            <div class="muted small">Periodic scans driven by APScheduler. Empty target list = scan all enabled devices.</div>
          </div>
        </div>
        <div id="sched-table">${loadingSkeleton(4)}</div>
      </div>
      <div class="glass card">
        <h2>Create / Update Schedule</h2>
        <div class="h-sub">Re-using an existing name updates the interval and targets in place.</div>
        <div class="form-row">
          <div class="field full"><label>Name</label><input id="s-name" placeholder="hourly-edge-audit" /></div>
          <div class="field"><label>Interval (minutes)</label><input id="s-interval" type="number" value="15" /></div>
          <div class="field"><label>Targets</label><input id="s-targets" placeholder="10.0.0.1, 10.0.0.2 (blank = all)" /></div>
        </div>
        <div class="row" style="margin-top:14px;gap:8px;justify-content:flex-end">
          <button class="btn primary" id="s-save">Save schedule</button>
        </div>
      </div>
    </div>
  `;

  document.getElementById("s-save").onclick = save;
  await reload();
}

async function reload() {
  try {
    _schedules = await api.listSchedules();
  } catch (e) {
    toast(`Failed to load schedules: ${e.message}`, "error");
    _schedules = [];
  }
  draw();
}

function draw() {
  const root = document.getElementById("sched-table");
  if (!root) return;
  if (!_schedules.length) {
    root.innerHTML = emptyState("⟳", "No scheduled scans yet.");
    return;
  }
  root.innerHTML = `<table class="table">
    <thead><tr>
      <th>Name</th><th>Interval</th><th>Targets</th><th>Last Run</th><th></th>
    </tr></thead>
    <tbody>
      ${_schedules.map(s => `<tr>
        <td><strong>${escapeHtml(s.name)}</strong></td>
        <td>${s.interval_minutes} min</td>
        <td>${(s.targets||[]).length ? s.targets.map(t=>`<span class="chip muted code">${escapeHtml(t)}</span>`).join(" ") : '<span class="muted small">all enabled</span>'}</td>
        <td class="muted small">${fmtTime(s.last_run_at)}</td>
        <td style="text-align:right">
          <button class="btn ghost small" data-id="${s.id}" style="color:var(--red)">Delete</button>
        </td>
      </tr>`).join("")}
    </tbody>
  </table>`;
  root.querySelectorAll("button[data-id]").forEach(b =>
    b.addEventListener("click", () => del(parseInt(b.dataset.id, 10)))
  );
}

async function save() {
  const name = document.getElementById("s-name").value.trim();
  const interval = parseInt(document.getElementById("s-interval").value, 10) || 15;
  const targetsRaw = document.getElementById("s-targets").value.trim();
  const targets = targetsRaw ? targetsRaw.split(/[\s,]+/).filter(Boolean) : [];
  if (!name) { toast("Name is required", "error"); return; }
  try {
    await api.createSchedule({ name, interval_minutes: interval, targets });
    toast("Schedule saved", "success");
    document.getElementById("s-name").value = "";
    document.getElementById("s-targets").value = "";
    await reload();
  } catch (e) { toast(`Save failed: ${e.message}`, "error"); }
}

async function del(id) {
  if (!confirm("Delete this schedule?")) return;
  try {
    await api.deleteSchedule(id);
    toast("Schedule deleted", "success");
    await reload();
  } catch (e) { toast(`Delete failed: ${e.message}`, "error"); }
}
