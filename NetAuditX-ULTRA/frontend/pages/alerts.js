import { api } from "/components/api.js";
import {
  fmtTime,
  fmtTimeAbsolute,
  loadingSkeleton,
  severityChip,
  emptyState,
  escapeHtml,
  toast,
} from "/components/ui.js";

let _alerts = [];
let _filter = "all";

export async function renderAlerts(view) {
  view.innerHTML = `
    <div class="glass card fade-in">
      <div class="row between" style="margin-bottom:14px;flex-wrap:wrap;gap:10px">
        <div>
          <h2 style="margin-bottom:2px">Alert History</h2>
          <div class="muted small">All fired alerts with delivery status and dedup fingerprints</div>
        </div>
        <div class="row" style="gap:6px">
          ${["all","critical","warning","info"].map(s =>
            `<button class="btn ghost small" data-sev="${s}">${s}</button>`).join("")}
        </div>
      </div>
      <div id="alerts-table">${loadingSkeleton(6)}</div>
    </div>
  `;
  view.querySelectorAll("button[data-sev]").forEach(b =>
    b.addEventListener("click", () => {
      _filter = b.dataset.sev;
      view.querySelectorAll("button[data-sev]").forEach(bb =>
        bb.classList.toggle("primary", bb.dataset.sev === _filter)
      );
      draw();
    })
  );
  view.querySelector('button[data-sev="all"]').classList.add("primary");

  await reload();
}

async function reload() {
  try {
    _alerts = await api.listAlerts({ limit: 200 });
  } catch (e) {
    toast(`Failed to load alerts: ${e.message}`, "error");
    _alerts = [];
  }
  draw();
}

function draw() {
  const root = document.getElementById("alerts-table");
  if (!root) return;
  const list = _alerts.filter(a => _filter === "all" ? true : a.severity === _filter);
  if (!list.length) {
    root.innerHTML = emptyState("✓", "No alerts in history.");
    return;
  }
  root.innerHTML = `<table class="table">
    <thead><tr>
      <th>Severity</th><th>Title</th><th>Target</th><th>Delivery</th><th>When</th>
    </tr></thead>
    <tbody>
      ${list.map(a => `<tr>
        <td>${severityChip(a.severity)}</td>
        <td>
          <div style="font-weight:600">${escapeHtml(a.title)}</div>
          <div class="muted small" style="margin-top:2px">${escapeHtml(a.message)}</div>
        </td>
        <td class="code">${escapeHtml(a.target || "—")}</td>
        <td>
          <span class="chip ${a.delivered_email?'success':'muted'}" style="margin-right:4px">
            <span class="dot"></span>email
          </span>
          <span class="chip ${a.delivered_webhook?'success':'muted'}">
            <span class="dot"></span>webhook
          </span>
        </td>
        <td class="muted small" title="${fmtTimeAbsolute(a.created_at)}">${fmtTime(a.created_at)}</td>
      </tr>`).join("")}
    </tbody>
  </table>`;
}
