// Tiny API client for the Spring Boot backend. Stores the JWT and role per browser tab (sessionStorage),
// attaches the token as a Bearer header, and centralizes error handling.
// NOTE: the role kept here only drives which buttons are shown. The backend enforces every permission.

const BASE = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8280/api";
// Matches next.config.js's basePath, so a raw location.href redirect lands on the right path
// (router.push() handles this on its own; a hard redirect from plain code does not).
const BASE_PATH = process.env.NEXT_PUBLIC_BASE_PATH ?? "/sentinelops";

export type Role = "ADMIN" | "MANAGER" | "TESTER" | "CLIENT";

export function getToken(): string | null {
  try { return sessionStorage.getItem("sentinelops_jwt"); } catch { return null; }
}
export function getRole(): Role | null {
  try { return sessionStorage.getItem("sentinelops_role") as Role | null; } catch { return null; }
}
export function setSession(token: string | null, role?: string | null) {
  try {
    if (token) {
      sessionStorage.setItem("sentinelops_jwt", token);
      if (role) sessionStorage.setItem("sentinelops_role", role);
    } else {
      sessionStorage.removeItem("sentinelops_jwt");
      sessionStorage.removeItem("sentinelops_role");
    }
  } catch { /* ignore */ }
}

/** Reads the "exp" claim out of the JWT payload without a library; returns null if it cannot be read. */
function tokenExpiry(token: string): number | null {
  try {
    const payload = token.split(".")[1];
    const json = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
    const exp = JSON.parse(json)?.exp;
    return typeof exp === "number" ? exp * 1000 : null;
  } catch { return null; }
}

function isExpired(token: string): boolean {
  const exp = tokenExpiry(token);
  return exp !== null && Date.now() >= exp;
}

/** Clears the session and sends the tab to the login page. Call this once a token is known to be stale. */
function signOutExpired() {
  setSession(null);
  try {
    const loginPath = `${BASE_PATH}/login`;
    if (!location.pathname.startsWith(loginPath)) {
      sessionStorage.setItem("sentinelops_expired", "1");
      location.href = loginPath;
    }
  } catch { /* ignore */ }
}

const SESSION_EXPIRED_MSG = "Your session expired. Signing you out.";

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json", ...(options.headers as any) };
  const token = getToken();
  if (token) {
    if (isExpired(token)) { signOutExpired(); throw new Error(SESSION_EXPIRED_MSG); }
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(`${BASE}${path}`, { ...options, headers });
  if (token && (res.status === 401 || res.status === 403)) {
    // A token that looked valid a moment ago but is now rejected has expired mid-session; sign out rather
    // than show a confusing "not allowed" for what is really an expired login.
    if (isExpired(getToken() || token)) { signOutExpired(); throw new Error(SESSION_EXPIRED_MSG); }
  }
  const text = await res.text();
  let body: any = null;
  try { body = text ? JSON.parse(text) : null; } catch { body = null; }
  if (!res.ok) {
    const fields = body?.fields ? " (" + Object.entries(body.fields).map(([k, v]) => `${k}: ${v}`).join("; ") + ")" : "";
    const msg = (body?.error || (res.status === 403 ? "Not allowed" : `Request failed (${res.status})`)) + fields;
    throw new Error(msg);
  }
  return body as T;
}

const post = (path: string, payload?: unknown) =>
  request<any>(path, { method: "POST", body: payload === undefined ? undefined : JSON.stringify(payload) });

const put = (path: string, payload?: unknown) =>
  request<any>(path, { method: "PUT", body: payload === undefined ? undefined : JSON.stringify(payload) });
const del = (path: string) => request<any>(path, { method: "DELETE" });

/** Downloads a PDF with the bearer token (a plain link cannot send it) and hands it to the browser. */
async function downloadPdf(path: string, fallbackName: string) {
  const token = getToken();
  if (token && isExpired(token)) { signOutExpired(); throw new Error(SESSION_EXPIRED_MSG); }
  const res = await fetch(`${BASE}${path}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
  if (token && (res.status === 401 || res.status === 403) && isExpired(token)) {
    signOutExpired();
    throw new Error(SESSION_EXPIRED_MSG);
  }
  if (!res.ok) {
    let msg = `Report failed (${res.status})`;
    try { msg = (await res.json()).error || msg; } catch { /* keep default */ }
    throw new Error(msg);
  }
  const m = /filename="?([^";]+)"?/.exec(res.headers.get("Content-Disposition") || "");
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url; a.download = m ? m[1] : fallbackName;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

export type Health ={ status: string; service: string; version: string; database: string; time: string };

export const api = {
  health: () => request<Health>("/health"),
  login: (email: string, password: string) =>
    request<{ token: string; role: Role; expiresInMinutes: number }>("/auth/login", {
      method: "POST", body: JSON.stringify({ email, password }),
    }),

  clients: () => request<any[]>("/clients"),
  createClient: (p: any) => post("/clients", p),

  engagements: () => request<any[]>("/engagements"),
  engagement: (id: string) => request<any>(`/engagements/${id}`),
  createEngagement: (p: any) => post("/engagements", p),
  findings: (id: string, f: { severity?: string; status?: string; tool?: string } = {}) => {
    const q = new URLSearchParams(Object.entries(f).filter(([, v]) => !!v) as [string, string][]).toString();
    return request<any[]>(`/engagements/${id}/findings${q ? "?" + q : ""}`);
  },
  finding: (id: string) => request<any>(`/findings/${id}`),
  validateFinding: (id: string, confirm: boolean, note?: string) => post(`/findings/${id}/validate`, { confirm, note }),
  setFindingStatus: (id: string, status: string, note?: string) => put(`/findings/${id}/status`, { status, note }),
  retestFinding: (id: string) => post(`/findings/${id}/retest`),
  dashboard: () => request<any>("/dashboard"),
  engagementDashboard: (id: string) => request<any>(`/engagements/${id}/dashboard`),
  downloadReport: (id: string, includeCandidates: boolean) =>
    downloadPdf(`/engagements/${id}/report?includeCandidates=${includeCandidates}`, "sentinelops-report.pdf"),

  schedules: (id: string) => request<any[]>(`/engagements/${id}/schedules`),
  createSchedule: (id: string, p: any) => post(`/engagements/${id}/schedules`, p),
  enableSchedule: (id: string, enabled: boolean) => put(`/schedules/${id}/enabled`, { enabled }),
  deleteSchedule: (id: string) => del(`/schedules/${id}`),
  credential: (id: string, tid: string) => request<any>(`/engagements/${id}/targets/${tid}/credential`),
  setCredential: (id: string, tid: string, headerName: string, value: string) =>
    put(`/engagements/${id}/targets/${tid}/credential`, { headerName, value }),
  deleteCredential: (id: string, tid: string) => del(`/engagements/${id}/targets/${tid}/credential`),
  setOpenApi: (id: string, tid: string, url: string) => put(`/engagements/${id}/targets/${tid}/openapi`, { url }),

  // Phase 0 of the logic-testing engine: test accounts on the target's own login (see PENTEST_COVERAGE_PLAN.md).
  testIdentities: (id: string, tid: string) => request<any[]>(`/engagements/${id}/targets/${tid}/identities`),
  createTestIdentity: (id: string, tid: string, p: any) => post(`/engagements/${id}/targets/${tid}/identities`, p),
  deleteTestIdentity: (id: string, tid: string, identityId: string) =>
    del(`/engagements/${id}/targets/${tid}/identities/${identityId}`),
  testIdentityLogin: (id: string, tid: string, identityId: string) =>
    post(`/engagements/${id}/targets/${tid}/identities/${identityId}/test-login`),
  // Phase 1: AUTH-11 (JWT manipulation) and AUTH-12 (logout session reuse).
  runAuthChecks: (id: string, tid: string, identityId: string) =>
    post(`/engagements/${id}/targets/${tid}/identities/${identityId}/auth-checks`),

  // Phase 2: ACC-01 / ACC-05 (IDOR, horizontal privilege escalation).
  idorProbes: (id: string, tid: string) => request<any[]>(`/engagements/${id}/targets/${tid}/idor-probes`),
  createIdorProbe: (id: string, tid: string, p: any) => post(`/engagements/${id}/targets/${tid}/idor-probes`, p),
  deleteIdorProbe: (id: string, tid: string, probeId: string) =>
    del(`/engagements/${id}/targets/${tid}/idor-probes/${probeId}`),
  runIdorProbe: (id: string, tid: string, probeId: string) =>
    post(`/engagements/${id}/targets/${tid}/idor-probes/${probeId}/run`),

  // Phase 3: FILE-06 (extension / type bypass on file upload).
  uploadProbes: (id: string, tid: string) => request<any[]>(`/engagements/${id}/targets/${tid}/upload-probes`),
  createUploadProbe: (id: string, tid: string, p: any) => post(`/engagements/${id}/targets/${tid}/upload-probes`, p),
  deleteUploadProbe: (id: string, tid: string, probeId: string) =>
    del(`/engagements/${id}/targets/${tid}/upload-probes/${probeId}`),
  runUploadProbe: (id: string, tid: string, probeId: string) =>
    post(`/engagements/${id}/targets/${tid}/upload-probes/${probeId}/run`),

  // Phase 4: checkout / business-logic probes (parameter tamper, reuse, race condition).
  businessProbes: (id: string, tid: string) => request<any[]>(`/engagements/${id}/targets/${tid}/business-probes`),
  createBusinessProbe: (id: string, tid: string, p: any) => post(`/engagements/${id}/targets/${tid}/business-probes`, p),
  deleteBusinessProbe: (id: string, tid: string, probeId: string) =>
    del(`/engagements/${id}/targets/${tid}/business-probes/${probeId}`),
  runBusinessProbe: (id: string, tid: string, probeId: string) =>
    post(`/engagements/${id}/targets/${tid}/business-probes/${probeId}/run`),

  // Phase 5: NET-09 DNS hygiene (SPF/DMARC) and NET-07 default service credentials.
  runDnsHygiene: (id: string, tid: string) => post(`/engagements/${id}/targets/${tid}/dns-hygiene-check`),
  runDefaultCredsCheck: (id: string, tid: string, identityId: string) =>
    post(`/engagements/${id}/targets/${tid}/identities/${identityId}/default-creds-check`),

  // Phase 6: dependency / SCA scanning (npm audit against an uploaded package-lock.json).
  dependencyManifests: (id: string, tid: string) => request<any[]>(`/engagements/${id}/targets/${tid}/dependency-manifests`),
  createDependencyManifest: (id: string, tid: string, p: any) => post(`/engagements/${id}/targets/${tid}/dependency-manifests`, p),
  deleteDependencyManifest: (id: string, tid: string, manifestId: string) =>
    del(`/engagements/${id}/targets/${tid}/dependency-manifests/${manifestId}`),
  runDependencyManifest: (id: string, tid: string, manifestId: string) =>
    post(`/engagements/${id}/targets/${tid}/dependency-manifests/${manifestId}/run`),
  scans: (id: string) => request<any[]>(`/engagements/${id}/scans`),
  stopScan: (runId: string) => post(`/scans/${runId}/stop`),

  targets: (id: string) => request<any[]>(`/engagements/${id}/targets`),
  registerTarget: (id: string, p: any) => post(`/engagements/${id}/targets`, p),
  startVerification: (id: string, targetId: string, method: string) =>
    post(`/engagements/${id}/targets/${targetId}/verification`, { method }),
  checkVerification: (id: string, targetId: string) =>
    post(`/engagements/${id}/targets/${targetId}/verification/check`),
  manualApproval: (id: string, targetId: string, p: any) =>
    post(`/engagements/${id}/targets/${targetId}/verification/manual`, p),
  gateCheck: (id: string, targetId: string, category: string, mode: string) =>
    post(`/engagements/${id}/targets/${targetId}/gate-check`, { category, mode }),

  authorizations: (id: string) => request<any[]>(`/engagements/${id}/authorizations`),
  createAuthorization: (id: string, p: any) => post(`/engagements/${id}/authorizations`, p),
  submitAuthorization: (authId: string) => post(`/authorizations/${authId}/submit`),
  approveAuthorization: (authId: string, note: string) => post(`/authorizations/${authId}/approve`, { note }),
  rejectAuthorization: (authId: string, note: string) => post(`/authorizations/${authId}/reject`, { note }),
  revokeAuthorization: (authId: string, note: string) => post(`/authorizations/${authId}/revoke`, { note }),

  scan: (id: string, p: { targetId: string; category: string; mode: string }) => post(`/engagements/${id}/scan`, p),

  users: () => request<any[]>("/users"),
  createUser: (p: any) => post("/users", p),
  settings: () => request<{ activeScanningEnabled: boolean }>("/settings"),
  setActiveScanning: (enabled: boolean) =>
    request<{ activeScanningEnabled: boolean }>("/settings/active-scanning", {
      method: "PUT", body: JSON.stringify({ enabled }),
    }),
  audit: (limit = 100) => request<any[]>(`/audit?limit=${limit}`),
};
