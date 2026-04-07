const API_URL = process.env.REACT_APP_API_URL || "https://policyguard-backend-mlwp.onrender.com";

function getToken() {
  return localStorage.getItem("policyguard_token") || "";
}

function setToken(token) {
  localStorage.setItem("policyguard_token", token);
}

function clearToken() {
  localStorage.removeItem("policyguard_token");
}

function getStoredUser() {
  try {
    const u = localStorage.getItem("policyguard_user");
    return u ? JSON.parse(u) : null;
  } catch (e) { return null; }
}

function setStoredUser(user) {
  localStorage.setItem("policyguard_user", JSON.stringify(user));
}

async function apiFetch(path, options = {}) {
  const token = getToken();
  const headers = { ...(options.headers || {}) };
  if (token) headers["Authorization"] = "Bearer " + token;
  if (!(options.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }
  const res = await fetch(API_URL + path, { ...options, headers });
  if (res.status === 401) {
    clearToken();
    window.location.reload();
    throw new Error("Session expired. Please log in again.");
  }
  if (!res.ok) {
    const text = await res.text();
    let detail = text;
    try { detail = JSON.parse(text).detail || text; } catch (e) {}
    throw new Error(detail);
  }
  return res.json();
}

// ─── Auth ───
export async function register(email, name, password) {
  const data = await apiFetch("/api/auth/register", {
    method: "POST",
    body: JSON.stringify({ email, name, password }),
  });
  setToken(data.access_token);
  setStoredUser(data.user);
  return data;
}

export async function login(email, password) {
  const formData = new URLSearchParams();
  formData.append("username", email);
  formData.append("password", password);
  const res = await fetch(API_URL + "/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: formData,
  });
  if (!res.ok) {
    const text = await res.text();
    let detail = text;
    try { detail = JSON.parse(text).detail || text; } catch (e) {}
    throw new Error(detail);
  }
  const data = await res.json();
  setToken(data.access_token);
  setStoredUser(data.user);
  return data;
}

export async function getMe() {
  return apiFetch("/api/auth/me");
}

export function logout() {
  clearToken();
  localStorage.removeItem("policyguard_user");
}

export function isLoggedIn() {
  return !!getToken();
}

export { getStoredUser };

// ─── Documents ───
export async function uploadDocument(file, docType, policySubtype, label) {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("doc_type", docType);
  if (policySubtype) formData.append("policy_subtype", policySubtype);
  if (label) formData.append("label", label);
  return apiFetch("/api/documents", { method: "POST", body: formData });
}

export async function listDocuments() {
  return apiFetch("/api/documents");
}

export async function getDocumentBase64(docId) {
  return apiFetch("/api/documents/" + docId + "/base64");
}

export async function deleteDocument(docId) {
  return apiFetch("/api/documents/" + docId, { method: "DELETE" });
}

export async function updateDocumentStatus(docId, status) {
  const formData = new FormData();
  formData.append("status", status);
  return apiFetch("/api/documents/" + docId + "/status", { method: "PATCH", body: formData });
}

// ─── Inventory ───
export async function createInventoryItem(item) {
  return apiFetch("/api/inventory", { method: "POST", body: JSON.stringify(item) });
}

export async function listInventory() {
  return apiFetch("/api/inventory");
}

export async function updateInventoryItem(itemId, item) {
  return apiFetch("/api/inventory/" + itemId, { method: "PUT", body: JSON.stringify(item) });
}

export async function uploadInventoryPhoto(itemId, file) {
  const formData = new FormData();
  formData.append("file", file);
  return apiFetch("/api/inventory/" + itemId + "/photo", { method: "POST", body: formData });
}

export async function deleteInventoryItem(itemId) {
  return apiFetch("/api/inventory/" + itemId, { method: "DELETE" });
}

// ─── Calendar ───
export async function createCalendarEvent(event) {
  return apiFetch("/api/calendar", { method: "POST", body: JSON.stringify(event) });
}

export async function listCalendarEvents() {
  return apiFetch("/api/calendar");
}

export async function updateCalendarEvent(eventId, event) {
  return apiFetch("/api/calendar/" + eventId, { method: "PUT", body: JSON.stringify(event) });
}

export async function deleteCalendarEvent(eventId) {
  return apiFetch("/api/calendar/" + eventId, { method: "DELETE" });
}

// ─── Analyses ───
export async function saveAnalysis(documentId, analysisJson) {
  return apiFetch("/api/analyses", {
    method: "POST",
    body: JSON.stringify({ document_id: documentId, analysis_json: JSON.stringify(analysisJson) }),
  });
}

export async function listAnalyses() {
  return apiFetch("/api/analyses");
}

export async function getAnalysis(docId) {
  return apiFetch("/api/analyses/" + docId);
}
