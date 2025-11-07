const API_BASE = "/api";

export async function checkSetup() {
  const res = await fetch(`${API_BASE}/setup`, { credentials: "include" });
  if (!res.ok) throw new Error("Abrufen des Setup-Status fehlgeschlagen.");
  return res.json();
}

export async function login(password: string) {
  const res = await fetch(`${API_BASE}/login`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password }),
  });
  if (!res.ok) {
    let msg = "Anmeldung fehlgeschlagen.";
    try {
      const err = await res.json().catch(() => null);
      const d = err?.detail ?? err?.message;
      if (typeof d === "string") msg = d; // technische provider/backend details zulassen
      else if (d) msg = JSON.stringify(d);
      else msg = res.statusText || msg;
    } catch (_) {}
    throw new Error(msg);
  }
  return res.json();
}

export async function logout() {
  const res = await fetch(`${API_BASE}/logout`, { method: "POST", credentials: "include" });
  if (!res.ok) {
    let msg = "Abmeldung fehlgeschlagen.";
    try {
      const err = await res.json().catch(() => null);
      const d = err?.detail ?? err?.message;
      if (typeof d === "string") msg = d; else if (d) msg = JSON.stringify(d);
    } catch (_) {}
    throw new Error(msg);
  }
  return res.json();
}

export async function getDomains() {
  const res = await fetch(`${API_BASE}/domains`, { credentials: "include" });
  if (!res.ok) {
    if (res.status === 401) throw new Error("Nicht autorisiert.");
    let msg = "Abrufen der Domains fehlgeschlagen.";
    try {
      const err = await res.json().catch(() => null);
      const d = err?.detail ?? err?.message;
      if (typeof d === "string") msg = d; else if (d) msg = JSON.stringify(d);
    } catch (_) {}
    throw new Error(msg);
  }
  return res.json();
}

export async function setup(password: string, api_key: string, api_secret: string, provider_name: string) {
  const res = await fetch(`${API_BASE}/setup`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password, api_key, api_secret, provider_name }),
  });
  if (!res.ok) {
    let msg = "Setup fehlgeschlagen.";
    try {
      const err = await res.json().catch(() => null);
      const d = err?.detail ?? err?.message;
      if (typeof d === "string") msg = d; else if (d) msg = JSON.stringify(d);
    } catch (_) {}
    throw new Error(msg);
  }
  return res.json();
}

export { API_BASE };

export async function refreshRecords(recordType?: string) {
  const qs = recordType ? `?record_type=${encodeURIComponent(recordType)}` : "";
  const res = await fetch(`${API_BASE}/records/refresh${qs}`, { method: "POST", credentials: "include" });
  if (!res.ok) {
    let msg = "Aktualisieren der Einträge fehlgeschlagen.";
    try {
      const err = await res.json().catch(() => null);
      const d = err?.detail ?? err?.message;
      if (typeof d === "string") msg = d; else if (d) msg = JSON.stringify(d);
    } catch (_) {}
    throw new Error(msg);
  }
  return res.json();
}

export async function getRecords(type = "A") {
  const res = await fetch(`${API_BASE}/records?record_type=${encodeURIComponent(type)}`, { credentials: "include" });
  if (!res.ok) {
    let msg = "Abrufen der Einträge fehlgeschlagen.";
    try {
      const err = await res.json().catch(() => null);
      const d = err?.detail ?? err?.message;
      if (typeof d === "string") msg = d; else if (d) msg = JSON.stringify(d);
    } catch (_) {}
    throw new Error(msg);
  }
  return res.json();
}

export async function getRecordsForDomain(type = "A", domain?: string) {
  const qs = [`record_type=${encodeURIComponent(type)}`];
  if (domain) qs.push(`domain=${encodeURIComponent(domain)}`);
  const res = await fetch(`${API_BASE}/records?${qs.join("&")}`, { credentials: "include" });
  if (!res.ok) {
    let msg = "Abrufen der Einträge fehlgeschlagen.";
    try {
      const err = await res.json().catch(() => null);
      const d = err?.detail ?? err?.message;
      if (typeof d === "string") msg = d; else if (d) msg = JSON.stringify(d);
    } catch (_) {}
    throw new Error(msg);
  }
  return res.json();
}

export async function deleteRecord(record: { domain: string; name: string; type: string; content?: string }) {
  const res = await fetch(`${API_BASE}/records`, {
    method: "DELETE",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(record),
  });
  if (!res.ok) {
    let msg = "Löschen des Eintrags fehlgeschlagen.";
    try {
      const err = await res.json().catch(() => null);
      const d = err?.detail ?? err?.message;
      if (typeof d === "string") msg = d; else if (d) msg = JSON.stringify(d);
    } catch (_) {}
    throw new Error(msg);
  }
  return res.json();
}
