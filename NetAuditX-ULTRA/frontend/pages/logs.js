// Live log streaming via Server-Sent Events.
import { api } from "/components/api.js";
import { escapeHtml } from "/components/ui.js";

export async function renderLogs(host) {
  host.innerHTML = `
    <div class="grid" style="gap:18px;">
      <div class="glass card">
        <div class="row between">
          <div>
            <h2 style="margin:0">Live SOC Console</h2>
            <div class="muted small">Streaming every backend log line as it happens.</div>
          </div>
          <div class="row" style="gap:8px;">
            <select class="select" id="lvl-filter">
              <option value="">All levels</option>
              <option value="DEBUG">DEBUG</option>
              <option value="INFO">INFO</option>
              <option value="WARNING">WARNING</option>
              <option value="ERROR">ERROR</option>
            </select>
            <button class="btn ghost sm" id="btn-pause">⏸ Pause</button>
            <button class="btn ghost sm" id="btn-clear">⌫ Clear</button>
            <span class="badge info" id="status-pill">connecting…</span>
          </div>
        </div>
      </div>
      <div class="terminal" id="term"></div>
    </div>
  `;

  const term = host.querySelector("#term");
  const status = host.querySelector("#status-pill");
  const lvlFilter = host.querySelector("#lvl-filter");
  const btnPause = host.querySelector("#btn-pause");
  const btnClear = host.querySelector("#btn-clear");

  let paused = false;
  let buffer = []; // collected while paused
  const MAX_LINES = 800;

  btnPause.addEventListener("click", () => {
    paused = !paused;
    btnPause.textContent = paused ? "▶ Resume" : "⏸ Pause";
    if (!paused && buffer.length) {
      buffer.forEach((r) => appendRecord(r));
      buffer = [];
      scrollToBottom();
    }
  });
  btnClear.addEventListener("click", () => (term.innerHTML = ""));
  lvlFilter.addEventListener("change", () => {
    term.querySelectorAll(".log-line").forEach((el) => {
      el.style.display = passesFilter(el.dataset.lvl) ? "" : "none";
    });
  });

  function passesFilter(lvl) {
    const sel = lvlFilter.value;
    return !sel || sel === lvl;
  }

  function appendRecord(rec) {
    if (rec.keepalive) return;
    const lvl = (rec.level || "INFO").toUpperCase();
    const ts = rec.ts ? new Date(rec.ts * 1000).toLocaleTimeString() : "";
    const line = document.createElement("div");
    line.className = `log-line ${lvl}`;
    line.dataset.lvl = lvl;
    line.innerHTML = `<span class="ts">${escapeHtml(ts)}</span><span class="lvl">${lvl}</span>${escapeHtml(rec.message || "")}`;
    if (!passesFilter(lvl)) line.style.display = "none";
    term.appendChild(line);
    while (term.childElementCount > MAX_LINES) term.firstChild.remove();
  }

  function scrollToBottom() {
    term.scrollTop = term.scrollHeight;
  }

  // Initial replay via plain fetch so we always get history even if SSE is slow.
  try {
    const recent = await api.recentLogs(150);
    (recent.items || []).forEach(appendRecord);
    scrollToBottom();
  } catch (_) { /* ignore */ }

  // Open SSE.
  let es;
  try {
    es = api.streamLogs(0); // we already replayed via /recent
  } catch (e) {
    status.textContent = "EventSource error";
    status.className = "badge critical";
    return;
  }

  es.onopen = () => {
    status.textContent = "● live";
    status.className = "badge success";
  };
  es.onerror = () => {
    status.textContent = "reconnecting…";
    status.className = "badge warning";
  };
  es.onmessage = (ev) => {
    let rec;
    try { rec = JSON.parse(ev.data); }
    catch { return; }
    if (paused) {
      buffer.push(rec);
      if (buffer.length > MAX_LINES) buffer = buffer.slice(-MAX_LINES);
      return;
    }
    appendRecord(rec);
    scrollToBottom();
  };

  // Cleanup when navigating away.
  return () => {
    try { es.close(); } catch (_) {}
  };
}
