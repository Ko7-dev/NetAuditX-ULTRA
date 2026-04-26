// Lightweight API client for NetAuditX backend.

const BASE = "/api";

async function request(path, opts = {}) {
  const res = await fetch(BASE + path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  const text = await res.text();
  let data;
  try {
    data = text ? JSON.parse(text) : null;
  } catch (_) {
    data = text;
  }
  if (!res.ok) {
    // Backend returns { ok:false, error:{ code, message, ... } }
    let detail =
      (data && data.error && data.error.message) ||
      (data && (data.detail || data.message)) ||
      `HTTP ${res.status}`;
    if (typeof detail !== "string") detail = JSON.stringify(detail);
    const err = new Error(detail);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

export const api = {
  health: () => request("/health"),
  stats: () => request("/dashboard/stats"),

  listDevices: () => request("/devices"),
  createDevice: (body) =>
    request("/devices", { method: "POST", body: JSON.stringify(body) }),
  updateDevice: (id, body) =>
    request(`/devices/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  deleteDevice: (id) => request(`/devices/${id}`, { method: "DELETE" }),

  triggerScan: (body = {}) =>
    request("/scan", { method: "POST", body: JSON.stringify(body) }),

  listResults: (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return request("/results" + (qs ? `?${qs}` : ""));
  },
  resultsStats: () => request("/results/stats"),

  latestInsight: () => request("/insights/latest"),
  listInsights: (limit = 20) => request(`/insights?limit=${limit}`),

  listAlerts: (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return request("/alerts" + (qs ? `?${qs}` : ""));
  },

  listSchedules: () => request("/scan/schedule"),
  createSchedule: (body) =>
    request("/scan/schedule", { method: "POST", body: JSON.stringify(body) }),
  deleteSchedule: (id) => request(`/scan/schedule/${id}`, { method: "DELETE" }),

  // ---- Discovery / Drift / Logs ----
  discover: (body) =>
    request("/discover", { method: "POST", body: JSON.stringify(body) }),
  listDrift: (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return request("/drift" + (qs ? `?${qs}` : ""));
  },
  driftStats: () => request("/drift/stats"),
  recentLogs: (limit = 200) => request(`/logs/recent?limit=${limit}`),
  streamLogs: (replay = 80) =>
    new EventSource(`${BASE}/logs/stream?replay=${replay}`),
};
