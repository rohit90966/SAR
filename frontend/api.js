const API_BASE = "http://localhost:8000";

function getToken() {
  return sessionStorage.getItem("jwt_token") || "";
}

function getAuthHeaders(extraHeaders = {}) {
  const token = getToken();
  return {
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...extraHeaders,
  };
}

async function apiFetch(path, options = {}) {
  const headers = getAuthHeaders(options.headers || {});
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  if (response.status === 401) {
    sessionStorage.removeItem("jwt_token");
    sessionStorage.removeItem("username");
    sessionStorage.removeItem("role");
    window.location.href = "index.html";
    throw new Error("Unauthorized");
  }

  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed with status ${response.status}`);
  }

  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/pdf")) {
    return response.blob();
  }
  if (contentType.includes("application/json")) {
    return response.json();
  }
  return response.text();
}

async function getCases() {
  return apiFetch("/cases", { method: "GET" });
}

async function getCase(id) {
  return apiFetch(`/cases/${id}`, { method: "GET" });
}

async function createCase(alert) {
  return apiFetch("/cases", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(alert),
  });
}

async function reviewCase(id, decision, comment, narrative) {
  return apiFetch(`/cases/${id}/review`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      analyst_id: sessionStorage.getItem("username") || "analyst",
      decision,
      comment,
      edited_narrative: narrative,
    }),
  });
}

async function replayCase(id) {
  return apiFetch(`/cases/${id}/replay`, { method: "POST" });
}

async function getAudit(id) {
  return apiFetch(`/cases/${id}/audit`, { method: "GET" });
}

async function exportPDF(id) {
  return apiFetch(`/cases/${id}/export/pdf`, { method: "GET" });
}

async function apiRequest(path, method = "GET", body = null) {
  const token = getToken();
  const options = {
    method,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
  };
  if (body) options.body = JSON.stringify(body);

  const BASE_URL = "http://localhost:8000";
  const response = await fetch(`${BASE_URL}${path}`, options);

  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(err.detail || `HTTP ${response.status}`);
  }
  return response.json();
}

export {
  API_BASE,
  getToken,
  apiFetch,
  getCases,
  getCase,
  createCase,
  reviewCase,
  replayCase,
  getAudit,
  exportPDF,
  apiRequest,
};
