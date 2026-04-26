import { api } from "/components/api.js";
import {
  fmtTimeAbsolute,
  fmtTime,
  loadingSkeleton,
  statusChip,
  emptyState,
  escapeHtml,
  toast,
  humanUptime,
} from "/components/ui.js";

let _results = [];
let _filter = "all";
let _selectedId = null;

export async function renderResults(view) {
  view.innerHTML = `
    <div class="grid cols-2 fade-in" style="grid-template-columns: 1.2fr 1fr;">
      <div class="glass card">
        <div class="row between" style="margin-bottom:14px">
          <div>
            <h2 style="margin-bottom:2px">Scan Results</h2>
            <div class="muted small">Structured outcome of every device probe</div>
          </div>
          <div class="row" style="gap:6px">
            ${["all","success","failed","offline"]
              .map(s => `<button class="btn ghost small" data-filter="${s}">${s}</button>`)
              .join("")}
          </div>
        </div>
        <div id="results-table">${loadingSkeleton(8)}</div>
      </div>

      <div class="glass card">
        <h2>Raw Output</h2>
        <div class="h-sub" id="raw-sub">Select a row to view sanitized command output.</div>
        <div id="raw-output" class="log-pre">${escapeHtml("// no row selected")}</div>
      </div>
    </div>
  `;

  view.querySelectorAll('button[data-filter]').forEach(b =>
    b.addEventListener("click", () => {
      _filter = b.dataset.filter;
      view.querySelectorAll('button[data-filter]').forEach(bb =>
        bb.classList.toggle("primary", bb.dataset.filter === _filter)
      );
      drawTable();
    })
  );
  view.querySelector('button[data-filter="all"]').classList.add("primary");

  await reload();
}

async function reload() {
  try {
    _results = await api.listResults({ limit: 200 });
  } catch (e) {
    toast(`Failed to load results: ${e.message}`, "error");
    _results = [];
  }
  drawTable();
}

function drawTable() {
  const root = document.getElementById("results-table");
  if (!root) return;
  const list = _results.filter(r => _filter === "all" ? true : r.status === _filter);
  if (!list.length) {
    root.innerHTML = emptyState("≣", "No matching scan results.");
    return;
  }
  root.innerHTML = `<table class="table">
    <thead><tr>
      <th>IP</th><th>Status</th><th>Vendor</th><th>Uptime</th><th>Duration</th><th>When</th>
    </tr></thead>
    <tbody>
      ${list.map(r => `<tr data-id="${r.id}" style="cursor:pointer">
        <td class="code">${escapeHtml(r.ip)}</td>
        <td>${statusChip(r.status)}</td>
        <td>${escapeHtml(r.vendor || "—")}</td>
        <td class="muted">${humanUptime(r.uptime_seconds)}</td>
        <td class="muted">${r.duration_ms ?? 0} ms</td>
        <td class="muted small" title="${fmtTimeAbsolute(r.created_at)}">${fmtTime(r.created_at)}</td>
      </tr>`).join("")}
    </tbody>
  </table>`;
  root.querySelectorAll("tr[data-id]").forEach(tr =>
    tr.addEventListener("click", () => showRaw(parseInt(tr.dataset.id, 10)))
  );

  // Auto-show first row.
  if (!_selectedId && list.length) {
    showRaw(list[0].id);
  } else if (_selectedId) {
    showRaw(_selectedId);
  }
}

function showRaw(id) {
  _selectedId = id;
  const r = _results.find(x => x.id === id);
  const out = document.getElementById("raw-output");
  const sub = document.getElementById("raw-sub");
  if (!r || !out) return;
  sub.textContent = `${r.ip} · ${r.status} · ${fmtTimeAbsolute(r.created_at)}`;
  if (r.error) {
    out.innerHTML = `<span style="color:var(--red)">[error]</span> ${escapeHtml(r.error)}\n\n${escapeHtml(r.raw_output || "")}`;
  } else {
    out.innerHTML = escapeHtml(r.raw_output || "// no output captured");
  }
}
