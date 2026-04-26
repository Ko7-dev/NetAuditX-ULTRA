// Shared UI helpers: toasts, icons, formatters, render helpers.

export function toast(message, type = "info", timeout = 3500) {
  const host = document.getElementById("toast-host");
  if (!host) return;
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = message;
  host.appendChild(el);
  setTimeout(() => {
    el.style.transition = "opacity 200ms";
    el.style.opacity = "0";
    setTimeout(() => el.remove(), 220);
  }, timeout);
}

export function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  const now = new Date();
  const diff = (now - d) / 1000;
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return d.toLocaleString();
}

export function fmtTimeAbsolute(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

export function humanUptime(seconds) {
  if (seconds == null || seconds < 0) return "—";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  const parts = [];
  if (days) parts.push(`${days}d`);
  if (hours) parts.push(`${hours}h`);
  if (mins || !parts.length) parts.push(`${mins}m`);
  return parts.join(" ");
}

export function statusChip(status) {
  if (!status) return `<span class="chip muted"><span class="dot"></span>unknown</span>`;
  const s = status.toLowerCase();
  return `<span class="chip ${s}"><span class="dot"></span>${s}</span>`;
}

export function severityChip(sev) {
  const s = (sev || "info").toLowerCase();
  return `<span class="chip ${s}"><span class="dot"></span>${s}</span>`;
}

export function severityBadge(sev, label) {
  const s = (sev || "info").toLowerCase();
  return `<span class="badge ${s}">${label != null ? label : s}</span>`;
}

export function statusBadge(status) {
  const s = (status || "unknown").toLowerCase();
  return `<span class="badge ${s}">${s}</span>`;
}

export function escapeHtml(str) {
  if (str == null) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function loadingSkeleton(rows = 4) {
  let html = "";
  for (let i = 0; i < rows; i++) {
    html += `<div class="skeleton" style="height:46px;margin-bottom:8px;"></div>`;
  }
  return html;
}

export function emptyState(big, label) {
  return `<div class="empty"><div class="big">${big}</div><div>${label}</div></div>`;
}
