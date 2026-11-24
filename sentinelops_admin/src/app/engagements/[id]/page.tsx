"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { SeverityBars, Stat } from "@/components/charts";
import {
  Badge, Btn, canDecide, Card, colors, Empty, Field, fmt, Grid, isStaff, Msg, useSession, useValidation,
} from "@/components/ui";

const METHODS = ["WEB", "API", "NETWORK", "TLS"];
const toIso = (local: string) => (local ? new Date(local).toISOString() : "");

// Where a message is shown. Each section of the page has its own, right under the button that caused it.
type Section = "register" | "panel" | "auth" | "authForm" | "scan" | "runs" | "schedList" | "sched" | "report" | "findings";
type Note = { err?: string | null; ok?: string | null };

// Values for our own practice target (OWASP Juice Shop in Docker, see lab/docker-compose.yml).
const JUICE_SHOP = { value: "172.28.0.10", baseUrl: "http://172.28.0.10:3000", label: "OWASP Juice Shop (lab)", lab: true };

export default function EngagementDetail({ params }: { params: { id: string } }) {
  const id = params.id;
  const { ready, role } = useSession();
  const [engagement, setEngagement] = useState<any>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [targets, setTargets] = useState<any[]>([]);
  const [auths, setAuths] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [fFilter, setFFilter] = useState<{ severity?: string; status?: string; tool?: string }>({});
  const [dash, setDash] = useState<any>(null);
  const [scheds, setScheds] = useState<any[]>([]);
  const [sForm, setSForm] = useState({ targetId: "", category: "WEB", mode: "PASSIVE", intervalDays: 7 });
  const [fDetail, setFDetail] = useState<any>(null);
  const [note, setNote] = useState("");
  const [runs, setRuns] = useState<any[]>([]);
  const [notes, setNotes] = useState<Partial<Record<Section, Note>>>({});
  const n = (s: Section): Note => notes[s] || {};

  // target registration
  const [tForm, setTForm] = useState({ value: "", baseUrl: "", label: "", lab: false });
  const vT = useValidation();
  // per-target panel
  const [panel, setPanel] = useState<{ targetId: string; kind: "verify" | "manual" | "gate" | "creds" | "identities" | "idor" | "upload" | "business" | "deps" } | null>(null);
  const [challenge, setChallenge] = useState<any>(null);
  const [manual, setManual] = useState({ approverName: "", approverContact: "", networkAckBy: "", evidenceRef: "", notes: "" });
  const vM = useValidation();
  const [gate, setGate] = useState({ category: "WEB", mode: "PASSIVE" });
  const [gateResult, setGateResult] = useState<any>(null);
  // authorization form
  const blank = {
    title: "", approverName: "", approverContact: "", emergencyContact: "", evidenceRef: "",
    windowStart: "", windowEnd: "", allowActive: false, allowAuthenticated: false, excluded: "", methods: ["WEB"] as string[], targetIds: [] as string[],
  };
  const [aForm, setAForm] = useState(blank);
  const vA = useValidation();
  // scan
  const [scan, setScan] = useState({ targetId: "", category: "WEB", mode: "PASSIVE" });
  const vS = useValidation();
  const vSch = useValidation();

  function load() {
    api.engagement(id).then(setEngagement).catch((e) => setLoadErr(e.message));
    api.targets(id).then(setTargets).catch(() => {});
    api.authorizations(id).then(setAuths).catch(() => {});
    api.findings(id, fFilter).then(setFindings).catch(() => {});
    api.engagementDashboard(id).then(setDash).catch(() => {});
    api.schedules(id).then(setScheds).catch(() => {});
    api.scans(id).then(setRuns).catch(() => {});
  }
  useEffect(() => { if (ready) load(); }, [ready, id, fFilter]);
  // While a scan is queued or running, refresh every few seconds.
  const busy = runs.some((r) => r.status === "QUEUED" || r.status === "RUNNING");
  useEffect(() => {
    if (!ready || !busy) return;
    const t = setInterval(load, 4000);
    return () => clearInterval(t);
  }, [ready, busy, id]);

  /** Runs an action and shows its result in `section` only (every other message is cleared). */
  async function run(section: Section, fn: () => Promise<any>, success?: string) {
    setNotes({});
    try {
      const r = await fn();
      if (success) setNotes({ [section]: { ok: success } });
      load();
      return r;
    } catch (e: any) {
      setNotes({ [section]: { err: e.message } });
      return null;
    }
  }
  const say = (section: Section, m: Note) => setNotes({ [section]: m });

  const targetName = (tid: string) => targets.find((t) => t.id === tid)?.value || tid;
  const canWork = isStaff(role);

  async function register(e: React.FormEvent) {
    e.preventDefault();
    setNotes({});
    if (!vT.check({ value: { label: "Target", value: tForm.value } })) return;
    const r = await run("register", () => api.registerTarget(id, tForm), "Target registered. It is NOT yet verified or authorized.");
    if (r) setTForm({ value: "", baseUrl: "", label: "", lab: false });
  }

  async function startVerify(t: any, method: string) {
    setPanel({ targetId: t.id, kind: "verify" });
    const r = await run("panel", () => api.startVerification(id, t.id, method));
    if (r) setChallenge(r);
  }
  async function checkNow(t: any) {
    const r = await run("panel", () => api.checkVerification(id, t.id));
    if (r) {
      setChallenge(r);
      if (r.status === "VERIFIED") say("panel", { ok: "Ownership verified." });
      else say("panel", { err: r.detail || "Not verified yet. The record or file was not found." });
    }
  }
  async function submitManual(e: React.FormEvent, t: any) {
    e.preventDefault();
    setNotes({});
    if (!vM.check({
      approverName: { label: "System owner name", value: manual.approverName },
      approverContact: { label: "Owner contact", value: manual.approverContact },
      networkAckBy: { label: "Network team acknowledged by", value: manual.networkAckBy },
      evidenceRef: { label: "Evidence reference", value: manual.evidenceRef },
    })) return;
    const r = await run("panel", () => api.manualApproval(id, t.id, manual), "Ownership approval recorded.");
    if (r) { setPanel(null); say("register", { ok: "Ownership approval recorded." }); }
  }
  async function doGate(t: any) {
    const r = await run("panel", () => api.gateCheck(id, t.id, gate.category, gate.mode));
    if (r) setGateResult(r);
  }

  // ---- DNS hygiene (Phase 5: NET-09; see PENTEST_COVERAGE_PLAN.md) ----
  const [dnsResult, setDnsResult] = useState<any>(null);
  const [dnsBusy, setDnsBusy] = useState(false);
  async function runDns(t: any) {
    setDnsBusy(true);
    try {
      const r = await api.runDnsHygiene(id, t.id);
      setDnsResult(r);
      if (r.vulnerableCount > 0) load();
    } catch (e: any) {
      setDnsResult({ error: e.message });
    } finally {
      setDnsBusy(false);
    }
  }

  // ---- credentials / OpenAPI ----
  const [cred, setCred] = useState<any>(null);
  const [credForm, setCredForm] = useState({ name: "Authorization", value: "" });
  const vC = useValidation();
  const [openApiUrl, setOpenApiUrl] = useState("");
  async function openCreds(t: any) {
    setPanel({ targetId: t.id, kind: "creds" });
    setCred(null); setOpenApiUrl(t.openApiUrl || ""); setCredForm({ name: "Authorization", value: "" }); vC.reset();
    try { setCred(await api.credential(id, t.id)); } catch (e: any) { say("panel", { err: e.message }); }
  }
  async function saveCred(e: React.FormEvent, t: any) {
    e.preventDefault();
    setNotes({});
    if (!vC.check({
      name: { label: "Header name", value: credForm.name },
      value: { label: "Header value", value: credForm.value },
    })) return;
    const r = await run("panel", () => api.setCredential(id, t.id, credForm.name, credForm.value), "Credential saved (encrypted). The value cannot be shown again.");
    setCredForm({ ...credForm, value: "" });
    if (r) setCred(await api.credential(id, t.id));
  }
  async function removeCred(t: any) {
    await run("panel", () => api.deleteCredential(id, t.id), "Credential removed.");
    setCred(await api.credential(id, t.id));
  }
  async function saveOpenApi(e: React.FormEvent, t: any) {
    e.preventDefault();
    await run("panel", () => api.setOpenApi(id, t.id, openApiUrl), openApiUrl ? "API definition saved." : "API definition cleared.");
  }

  // ---- test identities (Phase 0 of the logic-testing engine; see PENTEST_COVERAGE_PLAN.md) ----
  const [identities, setIdentities] = useState<any[]>([]);
  const blankIdentity = {
    label: "", loginUrl: "", usernameField: "email", passwordField: "password",
    username: "", password: "", tokenPath: "token", sessionType: "HEADER_BEARER",
    probeUrl: "", logoutUrl: "", logoutMethod: "POST",
  };
  const [idForm, setIdForm] = useState(blankIdentity);
  const vI = useValidation();
  const [loginResult, setLoginResult] = useState<Record<string, any>>({});
  async function openIdentities(t: any) {
    setPanel({ targetId: t.id, kind: "identities" });
    setIdForm({ ...blankIdentity, loginUrl: t.baseUrl ? t.baseUrl.replace(/\/$/, "") + "/login" : `https://${t.value}/login` });
    setLoginResult({});
    try { setIdentities(await api.testIdentities(id, t.id)); } catch (e: any) { say("panel", { err: e.message }); }
  }
  async function addIdentity(e: React.FormEvent, t: any) {
    e.preventDefault();
    setNotes({});
    if (!vI.check({
      label: { label: "Label", value: idForm.label },
      loginUrl: { label: "Login URL", value: idForm.loginUrl },
      username: { label: "Username", value: idForm.username },
      password: { label: "Password", value: idForm.password },
    })) return;
    const r = await run("panel", () => api.createTestIdentity(id, t.id, idForm), "Test identity saved. The password cannot be shown again.");
    if (r) { setIdForm({ ...blankIdentity, loginUrl: idForm.loginUrl }); setIdentities(await api.testIdentities(id, t.id)); }
  }
  async function removeIdentity(t: any, identityId: string) {
    await run("panel", () => api.deleteTestIdentity(id, t.id, identityId), "Test identity removed.");
    setIdentities(await api.testIdentities(id, t.id));
  }
  async function tryLogin(t: any, identityId: string) {
    setNotes({});
    try {
      const r = await api.testIdentityLogin(id, t.id, identityId);
      setLoginResult({ ...loginResult, [identityId]: r });
    } catch (e: any) {
      setLoginResult({ ...loginResult, [identityId]: { error: e.message } });
    }
  }
  const [defaultCredsResult, setDefaultCredsResult] = useState<Record<string, any>>({});
  const [defaultCredsBusy, setDefaultCredsBusy] = useState<string | null>(null);
  async function runDefaultCreds(t: any, identityId: string) {
    setNotes({});
    setDefaultCredsBusy(identityId);
    try {
      const r = await api.runDefaultCredsCheck(id, t.id, identityId);
      setDefaultCredsResult({ ...defaultCredsResult, [identityId]: r });
      if (r.vulnerableCount > 0) load();
    } catch (e: any) {
      setDefaultCredsResult({ ...defaultCredsResult, [identityId]: { error: e.message } });
    } finally {
      setDefaultCredsBusy(null);
    }
  }
  const [authCheckResult, setAuthCheckResult] = useState<Record<string, any>>({});
  const [authChecksBusy, setAuthChecksBusy] = useState<string | null>(null);
  async function runAuthChecks(t: any, identityId: string) {
    setNotes({});
    setAuthChecksBusy(identityId);
    try {
      const r = await api.runAuthChecks(id, t.id, identityId);
      setAuthCheckResult({ ...authCheckResult, [identityId]: r });
      if (r.vulnerableCount > 0) load(); // confirmed findings now exist; refresh the Findings card below
    } catch (e: any) {
      setAuthCheckResult({ ...authCheckResult, [identityId]: { error: e.message } });
    } finally {
      setAuthChecksBusy(null);
    }
  }

  // ---- IDOR probes (Phase 2 of the logic-testing engine; see PENTEST_COVERAGE_PLAN.md) ----
  const [idorProbesList, setIdorProbesList] = useState<any[]>([]);
  const blankIdor = { label: "", urlTemplate: "", identityAId: "", resourceIdA: "", identityBId: "", resourceIdB: "" };
  const [idorForm, setIdorForm] = useState(blankIdor);
  const vIdor = useValidation();
  const [idorResult, setIdorResult] = useState<Record<string, any>>({});
  const [idorBusy, setIdorBusy] = useState<string | null>(null);
  async function openIdor(t: any) {
    setPanel({ targetId: t.id, kind: "idor" });
    setIdorForm({ ...blankIdor, urlTemplate: t.baseUrl ? t.baseUrl.replace(/\/$/, "") + "/api/resource/{id}" : `https://${t.value}/api/resource/{id}` });
    setIdorResult({});
    try {
      const [probesList, idsList] = await Promise.all([api.idorProbes(id, t.id), api.testIdentities(id, t.id)]);
      setIdorProbesList(probesList);
      setIdentities(idsList); // the identity dropdowns below need the same list the "Test identities" panel uses
    } catch (e: any) { say("panel", { err: e.message }); }
  }
  async function addIdor(e: React.FormEvent, t: any) {
    e.preventDefault();
    setNotes({});
    if (!vIdor.check({
      label: { label: "Label", value: idorForm.label },
      urlTemplate: { label: "URL template", value: idorForm.urlTemplate },
      identityAId: { label: "Identity A", value: idorForm.identityAId },
      resourceIdA: { label: "A's own resource id", value: idorForm.resourceIdA },
      identityBId: { label: "Identity B", value: idorForm.identityBId },
      resourceIdB: { label: "B's own resource id", value: idorForm.resourceIdB },
    })) return;
    const r = await run("panel", () => api.createIdorProbe(id, t.id, idorForm), "IDOR probe saved.");
    if (r) { setIdorForm({ ...blankIdor, urlTemplate: idorForm.urlTemplate }); setIdorProbesList(await api.idorProbes(id, t.id)); }
  }
  async function removeIdor(t: any, probeId: string) {
    await run("panel", () => api.deleteIdorProbe(id, t.id, probeId), "IDOR probe removed.");
    setIdorProbesList(await api.idorProbes(id, t.id));
  }
  async function runIdor(t: any, probeId: string) {
    setNotes({});
    setIdorBusy(probeId);
    try {
      const r = await api.runIdorProbe(id, t.id, probeId);
      setIdorResult({ ...idorResult, [probeId]: r });
      if (r.vulnerableCount > 0) load();
    } catch (e: any) {
      setIdorResult({ ...idorResult, [probeId]: { error: e.message } });
    } finally {
      setIdorBusy(null);
    }
  }

  // ---- Upload probes (Phase 3 of the logic-testing engine; see PENTEST_COVERAGE_PLAN.md) ----
  const [uploadProbesList, setUploadProbesList] = useState<any[]>([]);
  const blankUpload = { label: "", uploadUrl: "", fieldName: "file", retrievalUrlTemplate: "", identityId: "" };
  const [uploadForm, setUploadForm] = useState(blankUpload);
  const vUpload = useValidation();
  const [uploadResult, setUploadResult] = useState<Record<string, any>>({});
  const [uploadBusy, setUploadBusy] = useState<string | null>(null);
  async function openUpload(t: any) {
    setPanel({ targetId: t.id, kind: "upload" });
    setUploadForm({
      ...blankUpload,
      uploadUrl: t.baseUrl ? t.baseUrl.replace(/\/$/, "") + "/upload" : `https://${t.value}/upload`,
      retrievalUrlTemplate: t.baseUrl ? t.baseUrl.replace(/\/$/, "") + "/uploads/{filename}" : `https://${t.value}/uploads/{filename}`,
    });
    setUploadResult({});
    try {
      const [probesList, idsList] = await Promise.all([api.uploadProbes(id, t.id), api.testIdentities(id, t.id)]);
      setUploadProbesList(probesList);
      setIdentities(idsList);
    } catch (e: any) { say("panel", { err: e.message }); }
  }
  async function addUpload(e: React.FormEvent, t: any) {
    e.preventDefault();
    setNotes({});
    if (!vUpload.check({
      label: { label: "Label", value: uploadForm.label },
      uploadUrl: { label: "Upload URL", value: uploadForm.uploadUrl },
      retrievalUrlTemplate: { label: "Retrieval URL template", value: uploadForm.retrievalUrlTemplate },
    })) return;
    const payload = { ...uploadForm, identityId: uploadForm.identityId || null };
    const r = await run("panel", () => api.createUploadProbe(id, t.id, payload), "Upload probe saved.");
    if (r) {
      setUploadForm({ ...blankUpload, uploadUrl: uploadForm.uploadUrl, retrievalUrlTemplate: uploadForm.retrievalUrlTemplate });
      setUploadProbesList(await api.uploadProbes(id, t.id));
    }
  }
  async function removeUpload(t: any, probeId: string) {
    await run("panel", () => api.deleteUploadProbe(id, t.id, probeId), "Upload probe removed.");
    setUploadProbesList(await api.uploadProbes(id, t.id));
  }
  async function runUpload(t: any, probeId: string) {
    setNotes({});
    setUploadBusy(probeId);
    try {
      const r = await api.runUploadProbe(id, t.id, probeId);
      setUploadResult({ ...uploadResult, [probeId]: r });
      if (r.vulnerableCount > 0) load();
    } catch (e: any) {
      setUploadResult({ ...uploadResult, [probeId]: { error: e.message } });
    } finally {
      setUploadBusy(null);
    }
  }

  // ---- Business logic probes (Phase 4 of the logic-testing engine; see PENTEST_COVERAGE_PLAN.md) ----
  const [businessProbesList, setBusinessProbesList] = useState<any[]>([]);
  const blankBusiness = {
    label: "", requestUrl: "", httpMethod: "POST", bodyTemplate: '{\n  "productId": "p1",\n  "price": 99.99,\n  "quantity": 1\n}',
    tamperedField: "price", tamperedValue: "0.01", concurrency: 5, identityId: "",
  };
  const [businessForm, setBusinessForm] = useState(blankBusiness);
  const vBusiness = useValidation();
  const [businessResult, setBusinessResult] = useState<Record<string, any>>({});
  const [businessBusy, setBusinessBusy] = useState<string | null>(null);
  async function openBusiness(t: any) {
    setPanel({ targetId: t.id, kind: "business" });
    setBusinessForm({ ...blankBusiness, requestUrl: t.baseUrl ? t.baseUrl.replace(/\/$/, "") + "/checkout" : `https://${t.value}/checkout` });
    setBusinessResult({});
    try {
      const [probesList, idsList] = await Promise.all([api.businessProbes(id, t.id), api.testIdentities(id, t.id)]);
      setBusinessProbesList(probesList);
      setIdentities(idsList);
    } catch (e: any) { say("panel", { err: e.message }); }
  }
  async function addBusiness(e: React.FormEvent, t: any) {
    e.preventDefault();
    setNotes({});
    if (!vBusiness.check({
      label: { label: "Label", value: businessForm.label },
      requestUrl: { label: "Request URL", value: businessForm.requestUrl },
      bodyTemplate: { label: "Body template", value: businessForm.bodyTemplate },
    })) return;
    const payload = {
      ...businessForm,
      identityId: businessForm.identityId || null,
      tamperedField: businessForm.tamperedField || null,
      tamperedValue: businessForm.tamperedField ? businessForm.tamperedValue : null,
      concurrency: Number(businessForm.concurrency) || 5,
    };
    const r = await run("panel", () => api.createBusinessProbe(id, t.id, payload), "Business logic probe saved.");
    if (r) {
      setBusinessForm({ ...blankBusiness, requestUrl: businessForm.requestUrl });
      setBusinessProbesList(await api.businessProbes(id, t.id));
    }
  }
  async function removeBusiness(t: any, probeId: string) {
    await run("panel", () => api.deleteBusinessProbe(id, t.id, probeId), "Business logic probe removed.");
    setBusinessProbesList(await api.businessProbes(id, t.id));
  }
  async function runBusiness(t: any, probeId: string) {
    setNotes({});
    setBusinessBusy(probeId);
    try {
      const r = await api.runBusinessProbe(id, t.id, probeId);
      setBusinessResult({ ...businessResult, [probeId]: r });
      if (r.vulnerableCount > 0) load();
    } catch (e: any) {
      setBusinessResult({ ...businessResult, [probeId]: { error: e.message } });
    } finally {
      setBusinessBusy(null);
    }
  }

  // ---- Dependency scanning (Phase 6 of the logic-testing engine; see PENTEST_COVERAGE_PLAN.md) ----
  const [depsList, setDepsList] = useState<any[]>([]);
  const blankDeps = { label: "", manifestContent: "" };
  const [depsForm, setDepsForm] = useState(blankDeps);
  const vDeps = useValidation();
  const [depsResult, setDepsResult] = useState<Record<string, any>>({});
  const [depsBusy, setDepsBusy] = useState<string | null>(null);
  async function openDeps(t: any) {
    setPanel({ targetId: t.id, kind: "deps" });
    setDepsForm(blankDeps);
    setDepsResult({});
    try { setDepsList(await api.dependencyManifests(id, t.id)); } catch (e: any) { say("panel", { err: e.message }); }
  }
  function onDepsFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => setDepsForm((f) => ({ ...f, manifestContent: String(reader.result || ""), label: f.label || file.name }));
    reader.readAsText(file);
  }
  async function addDeps(e: React.FormEvent, t: any) {
    e.preventDefault();
    setNotes({});
    if (!vDeps.check({
      label: { label: "Label", value: depsForm.label },
      manifestContent: { label: "package-lock.json content", value: depsForm.manifestContent },
    })) return;
    const r = await run("panel", () => api.createDependencyManifest(id, t.id, { ...depsForm, ecosystem: "NPM" }), "Manifest uploaded.");
    if (r) { setDepsForm(blankDeps); setDepsList(await api.dependencyManifests(id, t.id)); }
  }
  async function removeDeps(t: any, manifestId: string) {
    await run("panel", () => api.deleteDependencyManifest(id, t.id, manifestId), "Manifest removed.");
    setDepsList(await api.dependencyManifests(id, t.id));
  }
  async function runDeps(t: any, manifestId: string) {
    setNotes({});
    setDepsBusy(manifestId);
    try {
      const r = await api.runDependencyManifest(id, t.id, manifestId);
      setDepsResult({ ...depsResult, [manifestId]: r });
      if (r.vulnerableCount > 0) load();
    } catch (e: any) {
      setDepsResult({ ...depsResult, [manifestId]: { error: e.message } });
    } finally {
      setDepsBusy(null);
    }
  }

  async function createAuth(e: React.FormEvent) {
    e.preventDefault();
    setNotes({});
    const okFields = vA.check({
      title: { label: "Title", value: aForm.title },
      approverName: { label: "Client approver name", value: aForm.approverName },
      approverContact: { label: "Approver contact", value: aForm.approverContact },
      emergencyContact: { label: "Emergency contact", value: aForm.emergencyContact },
      evidenceRef: { label: "Evidence of approval", value: aForm.evidenceRef },
      windowStart: { label: "Testing starts", value: aForm.windowStart },
      windowEnd: { label: "Testing ends", value: aForm.windowEnd },
      methods: { label: "Permitted methods", value: aForm.methods },
      targetIds: { label: "Targets in scope", value: aForm.targetIds },
    });
    if (!okFields) return;
    if (new Date(aForm.windowEnd) <= new Date(aForm.windowStart)) {
      say("authForm", { err: "Testing ends must be after Testing starts." });
      return;
    }
    const payload = {
      title: aForm.title, approverName: aForm.approverName, approverContact: aForm.approverContact,
      emergencyContact: aForm.emergencyContact, evidenceRef: aForm.evidenceRef,
      permittedMethods: aForm.methods, targetIds: aForm.targetIds, allowActive: aForm.allowActive, allowAuthenticated: aForm.allowAuthenticated,
      excludedAssets: aForm.excluded.split(",").map((s) => s.trim()).filter(Boolean),
      windowStart: toIso(aForm.windowStart), windowEnd: toIso(aForm.windowEnd),
    };
    const r = await run("authForm", () => api.createAuthorization(id, payload), "Authorization drafted. Submit it for approval.");
    if (r) setAForm(blank);
  }
  const toggle = (list: string[], v: string) => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);
  const setA = (k: string, val: any) => { setAForm({ ...aForm, [k]: val }); vA.clear(k); };

  async function startScan(e: React.FormEvent) {
    e.preventDefault();
    setNotes({});
    if (!vS.check({ targetId: { label: "Target", value: scan.targetId } })) return;
    const r = await run("scan", () => api.scan(id, scan));
    if (r) say("scan", { ok: `Scan queued (${r.effectiveMode}): ${r.scanRunIds.length} run(s). Progress appears under "Scans" below.` });
  }

  const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"];
  const sortedFindings = [...findings].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
  const [openFinding, setOpenFinding] = useState<string | null>(null);

  if (!ready) return null;
  const mr = { marginTop: 14 } as const;

  return (
    <main className="page">
      <Link href="/" className="back">← Engagements</Link>
      <Msg err={loadErr} />
      {engagement && (
        <>
          <h1>{engagement.name}</h1>
          <p style={{ color: colors.muted, margin: "4px 0 0", display: "flex", gap: 10, alignItems: "center" }}>
            <Badge text={engagement.state} /> {engagement.environment}
          </p>
        </>
      )}

      {dash && (
        <Card title="Status">
          <Grid min={150}>
            <Stat label="Open findings" value={dash.summary.open} />
            <Stat label="Critical + High open" value={(dash.summary.openBySeverity.CRITICAL || 0) + (dash.summary.openBySeverity.HIGH || 0)}
                  color={(dash.summary.openBySeverity.CRITICAL || 0) + (dash.summary.openBySeverity.HIGH || 0) ? colors.bad : colors.ok} />
            <Stat label="Fixed, awaiting retest" value={dash.summary.awaitingRetest} color={colors.accent} />
            <Stat label="Resolved" value={dash.summary.resolved} color={colors.ok} />
            {canWork && <Stat label="Candidates to review" value={dash.summary.candidates} color={colors.warn} />}
            <Stat label="Targets verified" value={`${dash.summary.verifiedTargets}/${dash.summary.targets}`} />
          </Grid>
          <div style={{ marginTop: 14 }}><SeverityBars counts={dash.summary.openBySeverity} /></div>
        </Card>
      )}

      {/* ---------------- Targets ---------------- */}
      <Card step={1} title="Targets and ownership verification">
        <p className="help">
          Register a domain, IP or small range (/24 or smaller). Private, loopback, metadata and server addresses are refused.
          Registering a target gives <b>no</b> permission to scan it.
        </p>
        <div className="table-wrap">
          <table style={{ fontSize: 13 }}>
            <thead><tr><th>Target</th><th>Kind</th><th>Ownership</th><th>Valid until</th><th></th></tr></thead>
            <tbody>
              {targets.map((t) => (
                <tr key={t.id} style={{ borderTop: `1px solid ${colors.border}` }}>
                  <td><b>{t.value}</b>{t.label ? <span style={{ color: colors.muted }}> · {t.label}</span> : null}
                    {t.baseUrl && <div style={{ color: colors.muted, fontSize: 12 }}>{t.baseUrl}</div>}</td>
                  <td>{t.kind}</td><td><Badge text={t.status} /></td><td>{fmt(t.verificationExpiresAt)}</td>
                  <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                    {canWork && t.status !== "LAB" && t.kind === "DOMAIN" && (
                      <>
                        <Btn small kind="ghost" onClick={() => startVerify(t, "DNS_TXT")}>Verify via DNS</Btn>
                        <Btn small kind="ghost" onClick={() => startVerify(t, "HTTP_FILE")}>Verify via file</Btn>
                      </>
                    )}
                    {canDecide(role) && t.kind !== "DOMAIN" && t.status !== "LAB" && (
                      <Btn small kind="ghost" onClick={() => { vM.reset(); setNotes({}); setPanel({ targetId: t.id, kind: "manual" }); }}>Record owner approval</Btn>
                    )}
                    {canWork && <Btn small kind="ghost" onClick={() => { setGateResult(null); setDnsResult(null); setNotes({}); setPanel({ targetId: t.id, kind: "gate" }); }}>Gate check</Btn>}
                    {canWork && t.kind !== "CIDR" && <Btn small kind="ghost" onClick={() => { setNotes({}); openCreds(t); }}>Login &amp; API</Btn>}
                    {canWork && t.kind !== "CIDR" && <Btn small kind="ghost" onClick={() => { setNotes({}); openIdentities(t); }}>Test identities</Btn>}
                    {canWork && t.kind !== "CIDR" && <Btn small kind="ghost" onClick={() => { setNotes({}); openIdor(t); }}>IDOR probes</Btn>}
                    {canWork && t.kind !== "CIDR" && <Btn small kind="ghost" onClick={() => { setNotes({}); openUpload(t); }}>Upload probes</Btn>}
                    {canWork && t.kind !== "CIDR" && <Btn small kind="ghost" onClick={() => { setNotes({}); openBusiness(t); }}>Business logic probes</Btn>}
                    {canWork && <Btn small kind="ghost" onClick={() => { setNotes({}); openDeps(t); }}>Dependency scan</Btn>}
                  </td>
                </tr>
              ))}
              {targets.length === 0 && <tr><td colSpan={5}><Empty>No targets yet.</Empty></td></tr>}
            </tbody>
          </table>
        </div>

        {panel && (() => {
          const t = targets.find((x) => x.id === panel.targetId);
          if (!t) return null;
          return (
            <div className="panel-inline">
              <strong>{t.value}</strong>
              <Msg err={n("panel").err} ok={n("panel").ok} />
              {panel.kind === "verify" && challenge && (
                <div style={{ fontSize: 13, marginTop: 10 }}>
                  {challenge.recordName && (
                    <p>Create a DNS <b>TXT</b> record:<br />
                      Name: <code>{challenge.recordName}</code><br />
                      Value: <code>{challenge.recordValue}</code></p>
                  )}
                  {challenge.fileUrl && (
                    <p>Publish a text file at <code>{challenge.fileUrl}</code><br />
                      containing exactly: <code>{challenge.fileContent}</code></p>
                  )}
                  <p style={{ color: colors.muted }}>Token valid until {fmt(challenge.expiresAt)}. Status: <Badge text={challenge.status} />
                    {challenge.detail ? ` — ${challenge.detail}` : ""}</p>
                  <Btn small onClick={() => checkNow(t)}>Check now</Btn>
                  <Btn small kind="ghost" onClick={() => { setPanel(null); setChallenge(null); setNotes({}); }}>Close</Btn>
                </div>
              )}
              {panel.kind === "manual" && (
                <form onSubmit={(e) => submitManual(e, t)} noValidate style={{ marginTop: 10 }}>
                  <Grid min={220}>
                    <Field label="System owner name" required error={vM.errors.approverName}><input value={manual.approverName} onChange={(e) => { setManual({ ...manual, approverName: e.target.value }); vM.clear("approverName"); }} /></Field>
                    <Field label="Owner contact" required error={vM.errors.approverContact}><input value={manual.approverContact} onChange={(e) => { setManual({ ...manual, approverContact: e.target.value }); vM.clear("approverContact"); }} /></Field>
                    <Field label="Network team acknowledged by" required error={vM.errors.networkAckBy}><input value={manual.networkAckBy} onChange={(e) => { setManual({ ...manual, networkAckBy: e.target.value }); vM.clear("networkAckBy"); }} /></Field>
                    <Field label="Evidence reference" required error={vM.errors.evidenceRef} hint="Ticket or e-mail id"><input value={manual.evidenceRef} onChange={(e) => { setManual({ ...manual, evidenceRef: e.target.value }); vM.clear("evidenceRef"); }} /></Field>
                  </Grid>
                  <div style={mr}>
                    <Btn type="submit" small>Record approval</Btn>
                    <Btn small kind="ghost" onClick={() => { setPanel(null); setNotes({}); }}>Cancel</Btn>
                  </div>
                </form>
              )}
              {panel.kind === "creds" && (
                <div style={{ marginTop: 10, fontSize: 13 }}>
                  <p className="help">
                    <b>Authenticated scan.</b> One header (for example <code>Authorization: Bearer …</code> or a <code>Cookie</code>) that the
                    client gave us for a <b>test account</b>. It is stored encrypted, can never be read back, and is used only when a signed
                    authorization allows authenticated testing. Use a low-privilege test account, never a real admin.
                  </p>
                  <div style={{ marginBottom: 10 }}>
                    Current: {cred?.present ? <b>{cred.headerName} (value hidden), set by {cred.createdBy}</b> : "none"}{" "}
                    {cred?.present && <Btn small kind="ghost" onClick={() => removeCred(t)}>Remove</Btn>}
                  </div>
                  <form onSubmit={(e) => saveCred(e, t)} noValidate>
                    <Grid min={220}>
                      <Field label="Header name" required error={vC.errors.name}><input value={credForm.name} onChange={(e) => { setCredForm({ ...credForm, name: e.target.value }); vC.clear("name"); }} /></Field>
                      <Field label="Header value" required error={vC.errors.value}><input type="password" autoComplete="off" value={credForm.value} onChange={(e) => { setCredForm({ ...credForm, value: e.target.value }); vC.clear("value"); }} /></Field>
                    </Grid>
                    <div style={{ marginTop: 10 }}><Btn type="submit" small>Save credential</Btn></div>
                  </form>
                  <div className="sep">
                    <p className="help">
                      <b>API definition (OpenAPI / Swagger).</b> Must be on this target&apos;s own host. Used by the ACTIVE API scan only
                      (ZAP API scan); the passive API check does not need it.
                    </p>
                    <form onSubmit={(e) => saveOpenApi(e, t)} style={{ display: "flex", gap: 8 }}>
                      <input placeholder={`https://${t.value}/openapi.json`} value={openApiUrl} onChange={(e) => setOpenApiUrl(e.target.value)} />
                      <Btn type="submit" small>Save</Btn>
                    </form>
                  </div>
                  <div style={mr}><Btn small kind="ghost" onClick={() => { setPanel(null); setNotes({}); }}>Close</Btn></div>
                </div>
              )}
              {panel.kind === "identities" && (
                <div style={{ marginTop: 10, fontSize: 13 }}>
                  <p className="help">
                    <b>Test accounts (logic testing).</b> Store two or more accounts on this target&apos;s own login — for example
                    &quot;User A&quot; and &quot;User B&quot; — so later authorization/IDOR checks can act as each one and compare what they can
                    see. The password is encrypted and can never be read back. Using one to log in needs a signed authorization that
                    allows <b>authenticated</b> testing, same as a scan credential.
                  </p>
                  {identities.length === 0 && <p style={{ color: colors.muted, margin: "0 0 10px" }}>No test identities yet.</p>}
                  {identities.map((idt) => (
                    <div key={idt.id} style={{ borderTop: `1px solid ${colors.border}`, padding: "8px 0" }}>
                      <b>{idt.label}</b> <span style={{ color: colors.muted }}>— {idt.username} · {idt.loginUrl} · {idt.sessionType}</span>
                      {idt.probeUrl && <div style={{ color: colors.muted, fontSize: 12 }}>Probe: {idt.probeUrl}{idt.logoutUrl ? ` · Logout (${idt.logoutMethod}): ${idt.logoutUrl}` : ""}</div>}
                      <div style={{ marginTop: 4 }}>
                        <Btn small kind="ghost" onClick={() => tryLogin(t, idt.id)}>Test login</Btn>
                        <Btn small kind="ghost" disabled={authChecksBusy === idt.id} onClick={() => runAuthChecks(t, idt.id)}>
                          {authChecksBusy === idt.id ? "Running…" : "Run auth checks (AUTH-11, AUTH-12)"}
                        </Btn>
                        <Btn small kind="ghost" disabled={defaultCredsBusy === idt.id} onClick={() => runDefaultCreds(t, idt.id)}>
                          {defaultCredsBusy === idt.id ? "Checking…" : "Try default credentials (NET-07)"}
                        </Btn>
                        <Btn small kind="ghost" onClick={() => removeIdentity(t, idt.id)}>Remove</Btn>
                      </div>
                      {defaultCredsResult[idt.id] && (
                        <div style={{ marginTop: 4, fontSize: 12 }}>
                          {defaultCredsResult[idt.id].error ? (
                            <div style={{ color: colors.bad }}>{defaultCredsResult[idt.id].error}</div>
                          ) : defaultCredsResult[idt.id].checks.map((c: any) => (
                            <div key={c.checkId} style={{ display: "flex", gap: 8, alignItems: "baseline" }}>
                              <span style={{
                                color: c.verdict === "VULNERABLE" ? colors.bad : c.verdict === "NOT_VULNERABLE" ? colors.ok : colors.warn,
                                fontWeight: 600, minWidth: 130,
                              }}>{c.verdict.replace("_", " ")}</span>
                              <span>{c.description || c.title}</span>
                            </div>
                          ))}
                        </div>
                      )}
                      {loginResult[idt.id] && (
                        <div style={{ marginTop: 4, color: loginResult[idt.id].error || loginResult[idt.id].success === false ? colors.bad : colors.ok }}>
                          {loginResult[idt.id].error || loginResult[idt.id].detail}
                        </div>
                      )}
                      {authCheckResult[idt.id] && (
                        <div style={{ marginTop: 6, fontSize: 12 }}>
                          {authCheckResult[idt.id].error ? (
                            <div style={{ color: colors.bad }}>{authCheckResult[idt.id].error}</div>
                          ) : (
                            <>
                              {authCheckResult[idt.id].vulnerableCount > 0 && (
                                <div style={{ color: colors.bad, fontWeight: 600, marginBottom: 2 }}>
                                  {authCheckResult[idt.id].vulnerableCount} confirmed finding(s) added below.
                                </div>
                              )}
                              {authCheckResult[idt.id].checks.map((c: any) => (
                                <div key={c.checkId} style={{ display: "flex", gap: 8, alignItems: "baseline" }}>
                                  <span style={{
                                    color: c.verdict === "VULNERABLE" ? colors.bad : c.verdict === "NOT_VULNERABLE" ? colors.ok : colors.warn,
                                    fontWeight: 600, minWidth: 130,
                                  }}>{c.verdict.replace("_", " ")}</span>
                                  <span><b>{c.checkId}</b> {c.title}{c.description ? ` — ${c.description}` : ""}</span>
                                </div>
                              ))}
                            </>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                  <form onSubmit={(e) => addIdentity(e, t)} noValidate className="sep">
                    <strong>Add a test identity</strong>
                    <div style={{ height: 10 }} />
                    <Grid min={200}>
                      <Field label="Label" required error={vI.errors.label} hint="e.g. User A, Admin">
                        <input value={idForm.label} onChange={(e) => { setIdForm({ ...idForm, label: e.target.value }); vI.clear("label"); }} />
                      </Field>
                      <Field label="Login URL" required error={vI.errors.loginUrl} hint="Must be on this target's own host">
                        <input value={idForm.loginUrl} onChange={(e) => { setIdForm({ ...idForm, loginUrl: e.target.value }); vI.clear("loginUrl"); }} />
                      </Field>
                      <Field label="Username" required error={vI.errors.username}>
                        <input value={idForm.username} onChange={(e) => { setIdForm({ ...idForm, username: e.target.value }); vI.clear("username"); }} />
                      </Field>
                      <Field label="Password" required error={vI.errors.password}>
                        <input type="password" autoComplete="off" value={idForm.password} onChange={(e) => { setIdForm({ ...idForm, password: e.target.value }); vI.clear("password"); }} />
                      </Field>
                      <Field label="Username field name" hint="JSON field the login API expects">
                        <input value={idForm.usernameField} onChange={(e) => setIdForm({ ...idForm, usernameField: e.target.value })} />
                      </Field>
                      <Field label="Password field name">
                        <input value={idForm.passwordField} onChange={(e) => setIdForm({ ...idForm, passwordField: e.target.value })} />
                      </Field>
                      <Field label="Session type">
                        <select value={idForm.sessionType} onChange={(e) => setIdForm({ ...idForm, sessionType: e.target.value })}>
                          <option value="HEADER_BEARER">Token in JSON response (Bearer)</option>
                          <option value="COOKIE">Session cookie</option>
                        </select>
                      </Field>
                      {idForm.sessionType === "HEADER_BEARER" && (
                        <Field label="Token path" hint='Dot-path in the JSON response, e.g. "token" or "data.token"'>
                          <input value={idForm.tokenPath} onChange={(e) => setIdForm({ ...idForm, tokenPath: e.target.value })} />
                        </Field>
                      )}
                    </Grid>
                    <div className="sep">
                      <p className="help" style={{ marginTop: 0 }}>
                        Optional, needed only for <b>Run auth checks</b> below: a GET endpoint that requires authentication (used to
                        tell whether a session still works) and the endpoint that ends the session.
                      </p>
                      <Grid min={200}>
                        <Field label="Probe URL" hint="GET endpoint that requires authentication, e.g. /api/me">
                          <input value={idForm.probeUrl} onChange={(e) => setIdForm({ ...idForm, probeUrl: e.target.value })} />
                        </Field>
                        <Field label="Logout URL">
                          <input value={idForm.logoutUrl} onChange={(e) => setIdForm({ ...idForm, logoutUrl: e.target.value })} />
                        </Field>
                        <Field label="Logout method">
                          <select value={idForm.logoutMethod} onChange={(e) => setIdForm({ ...idForm, logoutMethod: e.target.value })}>
                            <option value="POST">POST</option>
                            <option value="GET">GET</option>
                          </select>
                        </Field>
                      </Grid>
                    </div>
                    <div style={mr}><Btn type="submit" small>Save identity</Btn></div>
                  </form>
                  <div style={mr}><Btn small kind="ghost" onClick={() => { setPanel(null); setNotes({}); }}>Close</Btn></div>
                </div>
              )}
              {panel.kind === "idor" && (
                <div style={{ marginTop: 10, fontSize: 13 }}>
                  <p className="help">
                    <b>Authorization / IDOR check (ACC-01, ACC-05).</b> Pick two test identities and, for each, the id of a
                    resource they own on this target (for example two different order numbers). The engine logs in as
                    each one, confirms they can read their own resource, then tries each one&apos;s id with the <b>other</b>&apos;s
                    session — the classic cross-account object check. Needs at least two test identities (see
                    &quot;Test identities&quot; above) and a signed authorization that allows ACTIVE and authenticated testing.
                  </p>
                  {identities.length < 2 && (
                    <p style={{ color: colors.warn, margin: "0 0 10px" }}>Add at least two test identities first.</p>
                  )}
                  {idorProbesList.length === 0 && <p style={{ color: colors.muted, margin: "0 0 10px" }}>No IDOR probes yet.</p>}
                  {idorProbesList.map((pr) => (
                    <div key={pr.id} style={{ borderTop: `1px solid ${colors.border}`, padding: "8px 0" }}>
                      <b>{pr.label}</b> <span style={{ color: colors.muted }}>— {pr.urlTemplate}</span>
                      <div style={{ color: colors.muted, fontSize: 12 }}>
                        A: {identities.find((x) => x.id === pr.identityAId)?.label || pr.identityAId} (id {pr.resourceIdA}) ·
                        {" "}B: {identities.find((x) => x.id === pr.identityBId)?.label || pr.identityBId} (id {pr.resourceIdB})
                      </div>
                      <div style={{ marginTop: 4 }}>
                        <Btn small kind="ghost" disabled={idorBusy === pr.id} onClick={() => runIdor(t, pr.id)}>
                          {idorBusy === pr.id ? "Running…" : "Run cross-access check"}
                        </Btn>
                        <Btn small kind="ghost" onClick={() => removeIdor(t, pr.id)}>Remove</Btn>
                      </div>
                      {idorResult[pr.id] && (
                        <div style={{ marginTop: 6, fontSize: 12 }}>
                          {idorResult[pr.id].error ? (
                            <div style={{ color: colors.bad }}>{idorResult[pr.id].error}</div>
                          ) : (
                            <>
                              {idorResult[pr.id].vulnerableCount > 0 && (
                                <div style={{ color: colors.bad, fontWeight: 600, marginBottom: 2 }}>
                                  {idorResult[pr.id].vulnerableCount} confirmed finding(s) added below.
                                </div>
                              )}
                              {idorResult[pr.id].checks.map((c: any) => (
                                <div key={c.checkId} style={{ display: "flex", gap: 8, alignItems: "baseline" }}>
                                  <span style={{
                                    color: c.verdict === "VULNERABLE" ? colors.bad : c.verdict === "NOT_VULNERABLE" ? colors.ok : colors.warn,
                                    fontWeight: 600, minWidth: 130,
                                  }}>{c.verdict.replace("_", " ")}</span>
                                  <span><b>{c.checkId}</b> {c.title}{c.description ? ` — ${c.description}` : ""}</span>
                                </div>
                              ))}
                            </>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                  <form onSubmit={(e) => addIdor(e, t)} noValidate className="sep">
                    <strong>Add an IDOR probe</strong>
                    <div style={{ height: 10 }} />
                    <Grid min={200}>
                      <Field label="Label" required error={vIdor.errors.label} hint="e.g. Order detail">
                        <input value={idorForm.label} onChange={(e) => { setIdorForm({ ...idorForm, label: e.target.value }); vIdor.clear("label"); }} />
                      </Field>
                      <Field label="URL template" required error={vIdor.errors.urlTemplate} hint={'Must contain "{id}" exactly once, on this target\'s own host'}>
                        <input value={idorForm.urlTemplate} onChange={(e) => { setIdorForm({ ...idorForm, urlTemplate: e.target.value }); vIdor.clear("urlTemplate"); }} />
                      </Field>
                      <Field label="Identity A" required error={vIdor.errors.identityAId}>
                        <select value={idorForm.identityAId} onChange={(e) => { setIdorForm({ ...idorForm, identityAId: e.target.value }); vIdor.clear("identityAId"); }}>
                          <option value="">Select…</option>
                          {identities.map((i) => <option key={i.id} value={i.id}>{i.label}</option>)}
                        </select>
                      </Field>
                      <Field label="A's own resource id" required error={vIdor.errors.resourceIdA} hint="e.g. 101">
                        <input value={idorForm.resourceIdA} onChange={(e) => { setIdorForm({ ...idorForm, resourceIdA: e.target.value }); vIdor.clear("resourceIdA"); }} />
                      </Field>
                      <Field label="Identity B" required error={vIdor.errors.identityBId}>
                        <select value={idorForm.identityBId} onChange={(e) => { setIdorForm({ ...idorForm, identityBId: e.target.value }); vIdor.clear("identityBId"); }}>
                          <option value="">Select…</option>
                          {identities.map((i) => <option key={i.id} value={i.id}>{i.label}</option>)}
                        </select>
                      </Field>
                      <Field label="B's own resource id" required error={vIdor.errors.resourceIdB} hint="e.g. 102, must differ from A's">
                        <input value={idorForm.resourceIdB} onChange={(e) => { setIdorForm({ ...idorForm, resourceIdB: e.target.value }); vIdor.clear("resourceIdB"); }} />
                      </Field>
                    </Grid>
                    <div style={mr}><Btn type="submit" small>Save probe</Btn></div>
                  </form>
                  <div style={mr}><Btn small kind="ghost" onClick={() => { setPanel(null); setNotes({}); }}>Close</Btn></div>
                </div>
              )}
              {panel.kind === "upload" && (
                <div style={{ marginTop: 10, fontSize: 13 }}>
                  <p className="help">
                    <b>File upload / extension bypass (FILE-06).</b> Uploads a small, harmless marker file under a
                    dangerous extension (e.g. <code>.php</code>) and a double extension (e.g. <code>.jpg.php</code>), then
                    tries to fetch it back at the retrieval URL. It only reports a problem when the exact bytes it sent
                    come back — never from the upload call alone returning success.
                  </p>
                  {uploadProbesList.length === 0 && <p style={{ color: colors.muted, margin: "0 0 10px" }}>No upload probes yet.</p>}
                  {uploadProbesList.map((pr) => (
                    <div key={pr.id} style={{ borderTop: `1px solid ${colors.border}`, padding: "8px 0" }}>
                      <b>{pr.label}</b> <span style={{ color: colors.muted }}>— {pr.uploadUrl} (field &quot;{pr.fieldName}&quot;)</span>
                      <div style={{ color: colors.muted, fontSize: 12 }}>
                        Retrieval: {pr.retrievalUrlTemplate} ·
                        {" "}{pr.identityId ? `as ${identities.find((x) => x.id === pr.identityId)?.label || pr.identityId}` : "anonymous"}
                      </div>
                      <div style={{ marginTop: 4 }}>
                        <Btn small kind="ghost" disabled={uploadBusy === pr.id} onClick={() => runUpload(t, pr.id)}>
                          {uploadBusy === pr.id ? "Running…" : "Run upload check"}
                        </Btn>
                        <Btn small kind="ghost" onClick={() => removeUpload(t, pr.id)}>Remove</Btn>
                      </div>
                      {uploadResult[pr.id] && (
                        <div style={{ marginTop: 6, fontSize: 12 }}>
                          {uploadResult[pr.id].error ? (
                            <div style={{ color: colors.bad }}>{uploadResult[pr.id].error}</div>
                          ) : (
                            <>
                              {uploadResult[pr.id].vulnerableCount > 0 && (
                                <div style={{ color: colors.bad, fontWeight: 600, marginBottom: 2 }}>
                                  {uploadResult[pr.id].vulnerableCount} confirmed finding(s) added below.
                                </div>
                              )}
                              {uploadResult[pr.id].checks.map((c: any) => (
                                <div key={c.checkId} style={{ display: "flex", gap: 8, alignItems: "baseline" }}>
                                  <span style={{
                                    color: c.verdict === "VULNERABLE" ? colors.bad : c.verdict === "NOT_VULNERABLE" ? colors.ok : colors.warn,
                                    fontWeight: 600, minWidth: 130,
                                  }}>{c.verdict.replace("_", " ")}</span>
                                  <span><b>{c.checkId}</b> {c.title}{c.description ? ` — ${c.description}` : ""}</span>
                                </div>
                              ))}
                            </>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                  <form onSubmit={(e) => addUpload(e, t)} noValidate className="sep">
                    <strong>Add an upload probe</strong>
                    <div style={{ height: 10 }} />
                    <Grid min={200}>
                      <Field label="Label" required error={vUpload.errors.label} hint="e.g. Avatar upload">
                        <input value={uploadForm.label} onChange={(e) => { setUploadForm({ ...uploadForm, label: e.target.value }); vUpload.clear("label"); }} />
                      </Field>
                      <Field label="Upload URL" required error={vUpload.errors.uploadUrl}>
                        <input value={uploadForm.uploadUrl} onChange={(e) => { setUploadForm({ ...uploadForm, uploadUrl: e.target.value }); vUpload.clear("uploadUrl"); }} />
                      </Field>
                      <Field label="Form field name" hint='The multipart field the API expects, e.g. "file"'>
                        <input value={uploadForm.fieldName} onChange={(e) => setUploadForm({ ...uploadForm, fieldName: e.target.value })} />
                      </Field>
                      <Field label="Retrieval URL template" required error={vUpload.errors.retrievalUrlTemplate} hint={'Must contain "{filename}" exactly once'}>
                        <input value={uploadForm.retrievalUrlTemplate} onChange={(e) => { setUploadForm({ ...uploadForm, retrievalUrlTemplate: e.target.value }); vUpload.clear("retrievalUrlTemplate"); }} />
                      </Field>
                      <Field label="Upload as" hint="Optional: a test identity's session, or leave blank for an anonymous upload">
                        <select value={uploadForm.identityId} onChange={(e) => setUploadForm({ ...uploadForm, identityId: e.target.value })}>
                          <option value="">Anonymous</option>
                          {identities.map((i) => <option key={i.id} value={i.id}>{i.label}</option>)}
                        </select>
                      </Field>
                    </Grid>
                    <div style={mr}><Btn type="submit" small>Save probe</Btn></div>
                  </form>
                  <div style={mr}><Btn small kind="ghost" onClick={() => { setPanel(null); setNotes({}); }}>Close</Btn></div>
                </div>
              )}
              {panel.kind === "business" && (
                <div style={{ marginTop: 10, fontSize: 13 }}>
                  <p className="help">
                    <b>Checkout / business logic (generalizes ECOM-02/03/04/05/09, BUS-03/07).</b> One request is replayed
                    three ways: as-is, with one field tampered (e.g. price set to 0.01), and several times at once. Each
                    needs its own working &quot;baseline&quot; call right before it to count as evidence — never a single odd
                    response. Because these are real actions (an order, a coupon), one check can use up shared state
                    (stock, a single coupon) that the next one needs — run probes one at a time against a resettable
                    test account when that matters.
                  </p>
                  {businessProbesList.length === 0 && <p style={{ color: colors.muted, margin: "0 0 10px" }}>No business logic probes yet.</p>}
                  {businessProbesList.map((pr) => (
                    <div key={pr.id} style={{ borderTop: `1px solid ${colors.border}`, padding: "8px 0" }}>
                      <b>{pr.label}</b> <span style={{ color: colors.muted }}>— {pr.httpMethod} {pr.requestUrl}</span>
                      <div style={{ color: colors.muted, fontSize: 12 }}>
                        {pr.tamperedField ? `Tamper: ${pr.tamperedField} → ${pr.tamperedValue} · ` : ""}
                        Concurrency: {pr.concurrency} ·
                        {" "}{pr.identityId ? `as ${identities.find((x) => x.id === pr.identityId)?.label || pr.identityId}` : "anonymous"}
                      </div>
                      <div style={{ marginTop: 4 }}>
                        <Btn small kind="ghost" disabled={businessBusy === pr.id} onClick={() => runBusiness(t, pr.id)}>
                          {businessBusy === pr.id ? "Running…" : "Run business logic check"}
                        </Btn>
                        <Btn small kind="ghost" onClick={() => removeBusiness(t, pr.id)}>Remove</Btn>
                      </div>
                      {businessResult[pr.id] && (
                        <div style={{ marginTop: 6, fontSize: 12 }}>
                          {businessResult[pr.id].error ? (
                            <div style={{ color: colors.bad }}>{businessResult[pr.id].error}</div>
                          ) : (
                            <>
                              {businessResult[pr.id].vulnerableCount > 0 && (
                                <div style={{ color: colors.bad, fontWeight: 600, marginBottom: 2 }}>
                                  {businessResult[pr.id].vulnerableCount} confirmed finding(s) added below.
                                </div>
                              )}
                              {businessResult[pr.id].checks.map((c: any) => (
                                <div key={c.checkId} style={{ display: "flex", gap: 8, alignItems: "baseline" }}>
                                  <span style={{
                                    color: c.verdict === "VULNERABLE" ? colors.bad : c.verdict === "NOT_VULNERABLE" ? colors.ok : colors.warn,
                                    fontWeight: 600, minWidth: 130,
                                  }}>{c.verdict.replace("_", " ")}</span>
                                  <span><b>{c.checkId}</b> {c.title}{c.description ? ` — ${c.description}` : ""}</span>
                                </div>
                              ))}
                            </>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                  <form onSubmit={(e) => addBusiness(e, t)} noValidate className="sep">
                    <strong>Add a business logic probe</strong>
                    <div style={{ height: 10 }} />
                    <Grid min={200}>
                      <Field label="Label" required error={vBusiness.errors.label} hint="e.g. Checkout">
                        <input value={businessForm.label} onChange={(e) => { setBusinessForm({ ...businessForm, label: e.target.value }); vBusiness.clear("label"); }} />
                      </Field>
                      <Field label="Request URL" required error={vBusiness.errors.requestUrl}>
                        <input value={businessForm.requestUrl} onChange={(e) => { setBusinessForm({ ...businessForm, requestUrl: e.target.value }); vBusiness.clear("requestUrl"); }} />
                      </Field>
                      <Field label="Method">
                        <select value={businessForm.httpMethod} onChange={(e) => setBusinessForm({ ...businessForm, httpMethod: e.target.value })}>
                          <option value="POST">POST</option>
                          <option value="PUT">PUT</option>
                        </select>
                      </Field>
                      <Field label="Concurrency" hint="2-10 parallel requests for the race check">
                        <input type="number" min={2} max={10} value={businessForm.concurrency}
                               onChange={(e) => setBusinessForm({ ...businessForm, concurrency: Number(e.target.value) })} />
                      </Field>
                      <Field label="Tampered field" hint="Optional: a top-level key in the body below, e.g. price">
                        <input value={businessForm.tamperedField} onChange={(e) => setBusinessForm({ ...businessForm, tamperedField: e.target.value })} />
                      </Field>
                      <Field label="Tampered value" hint='JSON value, e.g. 0.01, -5, true, or "CODE"'>
                        <input value={businessForm.tamperedValue} onChange={(e) => setBusinessForm({ ...businessForm, tamperedValue: e.target.value })} />
                      </Field>
                      <Field label="Send as" hint="Optional: a test identity's session, or leave blank for an anonymous request">
                        <select value={businessForm.identityId} onChange={(e) => setBusinessForm({ ...businessForm, identityId: e.target.value })}>
                          <option value="">Anonymous</option>
                          {identities.map((i) => <option key={i.id} value={i.id}>{i.label}</option>)}
                        </select>
                      </Field>
                    </Grid>
                    <div style={{ marginTop: 10 }}>
                      <Field label="Body template" required error={vBusiness.errors.bodyTemplate} hint="A valid JSON object; the tampered field must be one of its top-level keys">
                        <textarea rows={5} style={{ fontFamily: "monospace", fontSize: 12.5 }} value={businessForm.bodyTemplate}
                                  onChange={(e) => { setBusinessForm({ ...businessForm, bodyTemplate: e.target.value }); vBusiness.clear("bodyTemplate"); }} />
                      </Field>
                    </div>
                    <div style={mr}><Btn type="submit" small>Save probe</Btn></div>
                  </form>
                  <div style={mr}><Btn small kind="ghost" onClick={() => { setPanel(null); setNotes({}); }}>Close</Btn></div>
                </div>
              )}
              {panel.kind === "deps" && (
                <div style={{ marginTop: 10, fontSize: 13 }}>
                  <p className="help">
                    <b>Dependency scan (L: npm audit).</b> Upload a <code>package-lock.json</code> and it is checked against
                    npm&apos;s own advisory database. This never touches the target&apos;s live systems — only the public npm
                    registry — so it needs a signed authorization covering this target, but not ACTIVE or authenticated testing.
                  </p>
                  {depsList.length === 0 && <p style={{ color: colors.muted, margin: "0 0 10px" }}>No manifests uploaded yet.</p>}
                  {depsList.map((m) => (
                    <div key={m.id} style={{ borderTop: `1px solid ${colors.border}`, padding: "8px 0" }}>
                      <b>{m.label}</b> <span style={{ color: colors.muted }}>— {m.ecosystem} · {m.contentLength.toLocaleString()} characters</span>
                      <div style={{ marginTop: 4 }}>
                        <Btn small kind="ghost" disabled={depsBusy === m.id} onClick={() => runDeps(t, m.id)}>
                          {depsBusy === m.id ? "Scanning…" : "Run dependency scan"}
                        </Btn>
                        <Btn small kind="ghost" onClick={() => removeDeps(t, m.id)}>Remove</Btn>
                      </div>
                      {depsResult[m.id] && (
                        <div style={{ marginTop: 6, fontSize: 12 }}>
                          {depsResult[m.id].error ? (
                            <div style={{ color: colors.bad }}>{depsResult[m.id].error}</div>
                          ) : depsResult[m.id].checks.length === 0 ? (
                            <div style={{ color: colors.ok }}>No known vulnerabilities reported by npm.</div>
                          ) : (
                            <>
                              <div style={{ color: colors.bad, fontWeight: 600, marginBottom: 2 }}>
                                {depsResult[m.id].vulnerableCount} finding(s) added below.
                              </div>
                              {depsResult[m.id].checks.map((c: any, i: number) => (
                                <div key={i} style={{ display: "flex", gap: 8, alignItems: "baseline" }}>
                                  <span style={{ color: colors.bad, fontWeight: 600, minWidth: 70 }}>{c.severity}</span>
                                  <span>{c.title}</span>
                                </div>
                              ))}
                            </>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                  <form onSubmit={(e) => addDeps(e, t)} noValidate className="sep">
                    <strong>Upload a package-lock.json</strong>
                    <div style={{ height: 10 }} />
                    <Grid min={200}>
                      <Field label="Label" required error={vDeps.errors.label} hint="e.g. Backend lockfile">
                        <input value={depsForm.label} onChange={(e) => { setDepsForm({ ...depsForm, label: e.target.value }); vDeps.clear("label"); }} />
                      </Field>
                      <Field label="File">
                        <input type="file" accept=".json,application/json" onChange={onDepsFile} />
                      </Field>
                    </Grid>
                    {vDeps.errors.manifestContent && <div className="field-error" role="alert" style={{ marginTop: 6 }}>{vDeps.errors.manifestContent}</div>}
                    <div style={mr}><Btn type="submit" small>Upload</Btn></div>
                  </form>
                  <div style={mr}><Btn small kind="ghost" onClick={() => { setPanel(null); setNotes({}); }}>Close</Btn></div>
                </div>
              )}
              {panel.kind === "gate" && (
                <div style={{ marginTop: 10, fontSize: 13 }}>
                  <p className="help">Dry run: asks the authorization gate exactly what a real scan would ask. Nothing is scanned.</p>
                  <div className="row">
                    <select style={{ width: 140 }} value={gate.category} onChange={(e) => setGate({ ...gate, category: e.target.value })}>
                      {METHODS.map((m) => <option key={m}>{m}</option>)}
                    </select>
                    <select style={{ width: 140 }} value={gate.mode} onChange={(e) => setGate({ ...gate, mode: e.target.value })}>
                      <option>PASSIVE</option><option>ACTIVE</option>
                    </select>
                    <span>
                      <Btn small onClick={() => doGate(t)}>Check gate</Btn>
                      <Btn small kind="ghost" onClick={() => { setPanel(null); setNotes({}); }}>Close</Btn>
                    </span>
                  </div>
                  {gateResult && (
                    <p style={{ color: gateResult.allowed ? colors.ok : colors.bad, fontWeight: 600 }}>
                      {gateResult.allowed
                        ? `ALLOWED (${gateResult.effectiveMode}). Resolved: ${gateResult.resolvedAddresses.join(", ")}`
                        : `DENIED: ${gateResult.reason}`}
                    </p>
                  )}
                  {t.kind === "DOMAIN" && (
                    <div className="sep">
                      <p className="help" style={{ marginTop: 0 }}>
                        <b>DNS hygiene (NET-09).</b> Checks SPF and DMARC records for email-spoofing protection. Pure DNS
                        reads — nothing is sent to the target&apos;s application, so this needs only a signed authorization
                        covering NETWORK, not ACTIVE or authenticated testing.
                      </p>
                      <Btn small disabled={dnsBusy} onClick={() => runDns(t)}>{dnsBusy ? "Checking…" : "Run DNS hygiene check"}</Btn>
                      {dnsResult && (
                        <div style={{ marginTop: 8, fontSize: 12 }}>
                          {dnsResult.error ? (
                            <div style={{ color: colors.bad }}>{dnsResult.error}</div>
                          ) : (
                            <>
                              {dnsResult.vulnerableCount > 0 && (
                                <div style={{ color: colors.bad, fontWeight: 600, marginBottom: 2 }}>
                                  {dnsResult.vulnerableCount} confirmed finding(s) added below.
                                </div>
                              )}
                              {dnsResult.checks.map((c: any) => (
                                <div key={c.checkId} style={{ display: "flex", gap: 8, alignItems: "baseline" }}>
                                  <span style={{
                                    color: c.verdict === "VULNERABLE" ? colors.bad : c.verdict === "NOT_VULNERABLE" ? colors.ok : colors.warn,
                                    fontWeight: 600, minWidth: 130,
                                  }}>{c.verdict.replace("_", " ")}</span>
                                  <span><b>{c.checkId}</b> {c.title}{c.description ? ` — ${c.description}` : ""}</span>
                                </div>
                              ))}
                            </>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })()}

        {canWork && (
          <form onSubmit={register} noValidate className="sep">
            {role === "ADMIN" && (
              <div className="note-box" style={{ marginBottom: 14 }}>
                <b>Practice lab (OWASP Juice Shop).</b> Our own copy runs in Docker on a private lab network, so only a <b>lab asset</b> may use that
                address. Click the button to fill in the values, then press Register target.{" "}
                <Btn small kind="ghost" onClick={() => { setTForm(JUICE_SHOP); vT.reset(); setNotes({}); }}>Fill in Juice Shop values</Btn>
              </div>
            )}
            <Grid min={230}>
              <Field label="Target" required error={vT.errors.value} hint="A domain, URL, public IP or a /24 range. Not 127.0.0.1 or private addresses.">
                <input value={tForm.value} placeholder="app.example.com"
                       onChange={(e) => { setTForm({ ...tForm, value: e.target.value }); vT.clear("value"); }} />
              </Field>
              <Field label="Base URL" hint="Optional. Use it when the site is not on https port 443, e.g. http://host:3000. Must be on the target's own host.">
                <input value={tForm.baseUrl} placeholder="https://app.example.com"
                       onChange={(e) => setTForm({ ...tForm, baseUrl: e.target.value })} />
              </Field>
              <Field label="Label">
                <input value={tForm.label} placeholder="Optional" onChange={(e) => setTForm({ ...tForm, label: e.target.value })} />
              </Field>
              {role === "ADMIN" && (
                <Field label="Lab asset" hint="Our own practice target only. Allows the private lab address.">
                  <input type="checkbox" checked={tForm.lab} onChange={(e) => setTForm({ ...tForm, lab: e.target.checked })} /> This is a lab asset
                </Field>
              )}
            </Grid>
            <div style={mr}><Btn type="submit">Register target</Btn></div>
            <Msg err={n("register").err} ok={n("register").ok} />
          </form>
        )}
      </Card>

      {/* ---------------- Authorizations ---------------- */}
      <Card step={2} title="Written authorizations">
        <p className="help">
          Ownership proof is not permission. A scan needs a signed authorization covering the target, the method and the time window.
          Flow: draft → submit → approved by a manager/admin.
        </p>
        {auths.length === 0 && <Empty>No authorizations yet.</Empty>}
        {auths.map((a) => (
          <div key={a.id} style={{ borderTop: `1px solid ${colors.border}`, padding: "14px 0", fontSize: 13 }}>
            <div style={{ display: "flex", justifyContent: "space-between", gap: 10 }}>
              <strong style={{ fontSize: 14 }}>{a.title}</strong><Badge text={a.status} />
            </div>
            <div style={{ color: colors.muted, marginTop: 5, lineHeight: 1.7 }}>
              Methods: {a.permittedMethods.join(", ")} · Active: {a.allowActive ? "allowed" : "no"} · Authenticated: {a.allowAuthenticated ? "allowed" : "no"} · Window: {fmt(a.windowStart)} → {fmt(a.windowEnd)}<br />
              Targets: {a.targetIds.map(targetName).join(", ")}{a.excludedAssets.length ? ` · Excluded: ${a.excludedAssets.join(", ")}` : ""}<br />
              Approver: {a.approverName} ({a.approverContact}) · Emergency: {a.emergencyContact} · Evidence: {a.evidenceRef}<br />
              Requested by {a.requestedBy}{a.approvedBy ? ` · decided by ${a.approvedBy}` : ""}{a.decisionNote ? ` · "${a.decisionNote}"` : ""}
            </div>
            <div style={{ marginTop: 10 }}>
              {a.status === "DRAFT" && canWork && <Btn small onClick={() => run("auth", () => api.submitAuthorization(a.id), "Submitted for approval.")}>Submit for approval</Btn>}
              {a.status === "PENDING_APPROVAL" && canDecide(role) && (
                <>
                  <Btn small onClick={() => run("auth", () => api.approveAuthorization(a.id, "Approved"), "Authorization approved.")}>Approve</Btn>
                  <Btn small kind="danger" onClick={() => run("auth", () => api.rejectAuthorization(a.id, "Rejected"), "Authorization rejected.")}>Reject</Btn>
                </>
              )}
              {a.status === "SIGNED" && canDecide(role) && (
                <Btn small kind="danger" onClick={() => run("auth", () => api.revokeAuthorization(a.id, "Revoked"), "Authorization revoked.")}>Revoke</Btn>
              )}
            </div>
          </div>
        ))}
        <Msg err={n("auth").err} ok={n("auth").ok} />

        {canWork && (
          <form onSubmit={createAuth} noValidate className="sep">
            <strong style={{ fontSize: 14 }}>New authorization</strong>
            <div style={{ height: 12 }} />
            <Grid min={230}>
              <Field label="Title" required error={vA.errors.title}><input value={aForm.title} onChange={(e) => setA("title", e.target.value)} /></Field>
              <Field label="Client approver name" required error={vA.errors.approverName}><input value={aForm.approverName} onChange={(e) => setA("approverName", e.target.value)} /></Field>
              <Field label="Approver contact" required error={vA.errors.approverContact}><input value={aForm.approverContact} onChange={(e) => setA("approverContact", e.target.value)} /></Field>
              <Field label="Emergency contact" required error={vA.errors.emergencyContact}><input value={aForm.emergencyContact} onChange={(e) => setA("emergencyContact", e.target.value)} /></Field>
              <Field label="Evidence of approval" required error={vA.errors.evidenceRef} hint="Reference such as a ticket or e-mail id"><input value={aForm.evidenceRef} onChange={(e) => setA("evidenceRef", e.target.value)} /></Field>
              <Field label="Testing starts" required error={vA.errors.windowStart}><input type="datetime-local" value={aForm.windowStart} onChange={(e) => setA("windowStart", e.target.value)} /></Field>
              <Field label="Testing ends" required error={vA.errors.windowEnd}><input type="datetime-local" value={aForm.windowEnd} onChange={(e) => setA("windowEnd", e.target.value)} /></Field>
              <Field label="Excluded assets" hint="Comma separated"><input value={aForm.excluded} onChange={(e) => setA("excluded", e.target.value)} /></Field>
            </Grid>
            <div style={{ marginTop: 14, fontSize: 13 }}>
              <b>Permitted methods</b><span className="req">*</span>{" "}
              {METHODS.map((m) => (
                <label key={m} style={{ marginRight: 14 }}>
                  <input type="checkbox" checked={aForm.methods.includes(m)} onChange={() => setA("methods", toggle(aForm.methods, m))} /> {m}
                </label>
              ))}
              {vA.errors.methods && <div className="field-error" role="alert">{vA.errors.methods}</div>}
              <div style={{ marginTop: 8 }}>
                <label style={{ marginRight: 16 }}>
                  <input type="checkbox" checked={aForm.allowActive} onChange={(e) => setA("allowActive", e.target.checked)} /> allow ACTIVE testing
                </label>
                <label>
                  <input type="checkbox" checked={aForm.allowAuthenticated} onChange={(e) => setA("allowAuthenticated", e.target.checked)} /> allow AUTHENTICATED testing (a login/token the client gives us)
                </label>
              </div>
            </div>
            <div style={{ marginTop: 14, fontSize: 13 }}>
              <b>Targets in scope</b><span className="req">*</span>{" "}
              {targets.length === 0 && <span style={{ color: colors.muted }}>register a target first</span>}
              {targets.map((t) => (
                <label key={t.id} style={{ marginRight: 14 }}>
                  <input type="checkbox" checked={aForm.targetIds.includes(t.id)} onChange={() => setA("targetIds", toggle(aForm.targetIds, t.id))} /> {t.value}
                </label>
              ))}
              {vA.errors.targetIds && <div className="field-error" role="alert">{vA.errors.targetIds}</div>}
            </div>
            <div style={mr}><Btn type="submit">Create draft</Btn></div>
            <Msg err={n("authForm").err} ok={n("authForm").ok} />
          </form>
        )}
      </Card>

      {/* ---------------- Scan ---------------- */}
      {canWork && (
        <Card step={3} title="Start a scan">
          <p className="help">
            The gate must pass first. A permitted request is queued (one run per tool) and the background worker runs each tool in
            its own container. WEB = Nuclei + ZAP, API = Nuclei, TLS = testssl, NETWORK = Nmap. Only what the tools actually report is recorded.
          </p>
          <form onSubmit={startScan} noValidate>
            <div className="row" style={{ alignItems: "flex-start" }}>
              <div style={{ width: 260 }}>
                <Field label="Target" required error={vS.errors.targetId}>
                  <select value={scan.targetId} onChange={(e) => { setScan({ ...scan, targetId: e.target.value }); vS.clear("targetId"); }}>
                    <option value="">Select target…</option>
                    {targets.map((t) => <option key={t.id} value={t.id}>{t.value}</option>)}
                  </select>
                </Field>
              </div>
              <div style={{ width: 130 }}>
                <Field label="Method">
                  <select value={scan.category} onChange={(e) => setScan({ ...scan, category: e.target.value })}>
                    {METHODS.map((m) => <option key={m}>{m}</option>)}
                  </select>
                </Field>
              </div>
              <div style={{ width: 130 }}>
                <Field label="Mode">
                  <select value={scan.mode} onChange={(e) => setScan({ ...scan, mode: e.target.value })}>
                    <option>PASSIVE</option><option>ACTIVE</option>
                  </select>
                </Field>
              </div>
            </div>
            <div style={mr}><Btn type="submit">Request scan</Btn></div>
            <Msg err={n("scan").err} ok={n("scan").ok} />
          </form>
        </Card>
      )}

      {/* ---------------- Scans ---------------- */}
      <Card title="Scans" right={<Btn kind="ghost" small onClick={load}>Refresh</Btn>}>
        {runs.length === 0
          ? <Empty>No scans yet.</Empty>
          : runs.map((r) => (
            <div key={r.id} style={{ fontSize: 13, padding: "10px 0", borderBottom: `1px solid ${colors.border}` }}>
              <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                <Badge text={r.status} />
                <b>{r.tool}</b> · {r.category} · {r.mode}{r.purpose && r.purpose !== "SCAN" ? ` · ${r.purpose.toLowerCase()}` : ""} · {r.targetHost}
                <span style={{ color: colors.muted }}>
                  started {fmt(r.startedAt)} · ended {fmt(r.endedAt)}{r.status === "COMPLETED" ? ` · ${r.findingCount} finding(s)` : ""}
                </span>
                {canWork && (r.status === "QUEUED" || r.status === "RUNNING") && (
                  <Btn kind="ghost" small onClick={() => run("runs", () => api.stopScan(r.id), "Scan stopped.")}>Stop</Btn>
                )}
              </div>
              {r.error && <div style={{ color: colors.bad, marginTop: 4 }}>{r.error}</div>}
            </div>
          ))}
        <Msg err={n("runs").err} ok={n("runs").ok} />
      </Card>

      {/* ---------------- Schedules ---------------- */}
      {canWork && (
        <Card title="Recurring scans">
          <p className="help">
            A schedule only asks for a scan on time. Every run still passes the full gate (verified ownership, signed
            authorization, window, method, fresh DNS). After 3 refusals in a row it switches itself off.
          </p>
          {scheds.map((s) => (
            <div key={s.id} style={{ fontSize: 13, padding: "8px 0", borderBottom: `1px solid ${colors.border}` }}>
              <b>{targetName(s.targetId)}</b> · {s.category} · {s.mode} · every {s.intervalDays} day(s) · next {fmt(s.nextRunAt)}{" "}
              {s.enabled ? <Badge text="COMPLETED" /> : <Badge text="STOPPED" />}
              <span style={{ marginLeft: 8 }}>
                <Btn small kind="ghost" onClick={() => run("schedList", () => api.enableSchedule(s.id, !s.enabled))}>{s.enabled ? "Pause" : "Resume"}</Btn>
                <Btn small kind="ghost" onClick={() => run("schedList", () => api.deleteSchedule(s.id), "Schedule deleted.")}>Delete</Btn>
              </span>
              {s.lastResult && <div style={{ color: colors.muted }}>Last: {s.lastResult}</div>}
            </div>
          ))}
          <Msg err={n("schedList").err} ok={n("schedList").ok} />
          <form noValidate className="sep"
                onSubmit={(e) => {
                  e.preventDefault();
                  setNotes({});
                  if (!vSch.check({
                    targetId: { label: "Target", value: sForm.targetId },
                    intervalDays: { label: "Repeat every (days)", value: String(sForm.intervalDays || "") },
                  })) return;
                  run("sched", () => api.createSchedule(id, { ...sForm, intervalDays: Number(sForm.intervalDays) }), "Schedule created. First run in about 10 minutes.");
                }}>
            <div className="row" style={{ alignItems: "flex-start" }}>
              <div style={{ width: 240 }}>
                <Field label="Target" required error={vSch.errors.targetId}>
                  <select value={sForm.targetId} onChange={(e) => { setSForm({ ...sForm, targetId: e.target.value }); vSch.clear("targetId"); }}>
                    <option value="">Select target…</option>
                    {targets.map((t) => <option key={t.id} value={t.id}>{t.value}</option>)}
                  </select>
                </Field>
              </div>
              <div style={{ width: 120 }}>
                <Field label="Method">
                  <select value={sForm.category} onChange={(e) => setSForm({ ...sForm, category: e.target.value })}>
                    {METHODS.map((m) => <option key={m}>{m}</option>)}
                  </select>
                </Field>
              </div>
              <div style={{ width: 120 }}>
                <Field label="Mode">
                  <select value={sForm.mode} onChange={(e) => setSForm({ ...sForm, mode: e.target.value })}>
                    <option>PASSIVE</option><option>ACTIVE</option>
                  </select>
                </Field>
              </div>
              <div style={{ width: 150 }}>
                <Field label="Repeat every (days)" required error={vSch.errors.intervalDays}>
                  <input type="number" min={1} max={365} value={sForm.intervalDays}
                         onChange={(e) => { setSForm({ ...sForm, intervalDays: Number(e.target.value) }); vSch.clear("intervalDays"); }} />
                </Field>
              </div>
            </div>
            <div style={mr}><Btn type="submit">Add schedule</Btn></div>
            <Msg err={n("sched").err} ok={n("sched").ok} />
          </form>
        </Card>
      )}

      {/* ---------------- Findings ---------------- */}
      <Card title={`Findings (${findings.length})`}
            right={
              <span>
                <Btn small kind="ghost" onClick={() => run("report", () => api.downloadReport(id, false), "Report downloaded (confirmed findings only).")}>PDF report</Btn>
                {canWork && <Btn small kind="ghost" onClick={() => run("report", () => api.downloadReport(id, true), "Draft report downloaded, including UNCONFIRMED findings.")}>Draft incl. candidates</Btn>}
              </span>
            }>
        <p className="help">
          {canWork
            ? <>Scanner output is a <b>candidate</b> until you confirm it; clients only see confirmed findings. The same issue found again is not duplicated.
                After a fix is reported, <b>Request retest</b> re-runs only the tool that found it.</>
            : <>Reported issues with how to fix them. Mark an issue <b>In progress</b> or <b>Fixed</b> when you act on it; a tester will re-check it.</>}
        </p>
        <Msg err={n("report").err} ok={n("report").ok} />
        <div className="row" style={{ margin: "12px 0" }}>
          <select style={{ width: 160 }} value={fFilter.severity || ""} onChange={(e) => setFFilter({ ...fFilter, severity: e.target.value || undefined })}>
            <option value="">All severities</option>
            {SEV_ORDER.map((s) => <option key={s}>{s}</option>)}
          </select>
          <select style={{ width: 170 }} value={fFilter.status || ""} onChange={(e) => setFFilter({ ...fFilter, status: e.target.value || undefined })}>
            <option value="">All statuses</option>
            {["OPEN", "IN_PROGRESS", "FIXED", "RETEST_PASS", "RETEST_FAIL", "CLOSED", "FALSE_POSITIVE"].map((s) => <option key={s}>{s}</option>)}
          </select>
          <select style={{ width: 140 }} value={fFilter.tool || ""} onChange={(e) => setFFilter({ ...fFilter, tool: e.target.value || undefined })}>
            <option value="">All tools</option>
            {["nuclei", "zap", "zap-api", "testssl", "nmap", "auth-logic", "idor-logic", "upload-logic", "biz-logic", "dns-hygiene", "default-creds", "dependency-scan"].map((s) => <option key={s}>{s}</option>)}
          </select>
        </div>
        {findings.length === 0
          ? <Empty>No findings.</Empty>
          : sortedFindings.map((f) => (
            <div key={f.id} style={{ fontSize: 13, padding: "10px 0", borderBottom: `1px solid ${colors.border}` }}>
              <div style={{ display: "flex", gap: 10, alignItems: "center", cursor: "pointer", flexWrap: "wrap" }}
                   onClick={async () => {
                     setNotes({});
                     if (openFinding === f.id) { setOpenFinding(null); setFDetail(null); return; }
                     setOpenFinding(f.id); setNote("");
                     try { setFDetail(await api.finding(f.id)); } catch { setFDetail(null); }
                   }}>
                <Badge text={f.severity} />
                <Badge text={f.status} />
                {!f.validated && <span style={{ fontSize: 11, color: colors.warn, fontWeight: 600 }}>UNCONFIRMED</span>}
                <b>{f.title}</b>
                <span style={{ color: colors.muted }}>{f.tool} · last seen {fmt(f.lastSeenAt)}</span>
              </div>
              {openFinding === f.id && (
                <div style={{ marginTop: 10, paddingLeft: 4, lineHeight: 1.6 }}>
                  {f.location && <div><b>Where:</b> <span style={{ wordBreak: "break-all" }}>{f.location}</span></div>}
                  {f.description && <div><b>What:</b> {f.description}</div>}
                  {f.remediation && <div><b>How to fix:</b> {f.remediation}</div>}
                  {f.referenceIds && <div style={{ color: colors.muted }}><b>References:</b> {f.referenceIds}</div>}
                  {f.fixNotes && <div><b>Notes:</b> {f.fixNotes}</div>}
                  {fDetail?.retests?.length > 0 && (
                    <div style={{ marginTop: 4 }}><b>Retests:</b>
                      {fDetail.retests.map((r: any, i: number) => (
                        <div key={i} style={{ color: r.result === "PASS" ? colors.ok : colors.bad }}>
                          {fmt(r.testedAt)} · {r.result} · {r.notes}
                        </div>
                      ))}
                    </div>
                  )}
                  <div className="row" style={{ marginTop: 10 }}>
                    <input style={{ width: 260 }} placeholder="Note (optional)" value={note} onChange={(e) => setNote(e.target.value)} />
                    {canWork && !f.validated && f.status !== "FALSE_POSITIVE" && (
                      <span>
                        <Btn small onClick={() => run("findings", () => api.validateFinding(f.id, true, note), "Confirmed. The client can now see it.")}>Confirm</Btn>
                        <Btn small kind="ghost" onClick={() => run("findings", () => api.validateFinding(f.id, false, note), "Dismissed as a false positive.")}>False positive</Btn>
                      </span>
                    )}
                    {(canWork ? f.validated || true : f.validated) && [
                      f.status === "OPEN" || f.status === "RETEST_FAIL" ? ["IN_PROGRESS", "Start fixing"] : null,
                      f.status === "OPEN" || f.status === "IN_PROGRESS" || f.status === "RETEST_FAIL" ? ["FIXED", "Mark fixed"] : null,
                      canWork && f.status === "RETEST_PASS" ? ["CLOSED", "Close"] : null,
                      canWork && (f.status === "CLOSED" || f.status === "FALSE_POSITIVE" || f.status === "FIXED") ? ["OPEN", "Reopen"] : null,
                    ].filter(Boolean).map((x: any) => (
                      <Btn key={x[0]} small kind="ghost" onClick={() => run("findings", () => api.setFindingStatus(f.id, x[0], note), `Status: ${x[0]}`)}>{x[1]}</Btn>
                    ))}
                    {canWork && f.status === "FIXED" && (
                      <Btn small onClick={async () => {
                        const r = await run("findings", () => api.retestFinding(f.id));
                        if (r) say("findings", { ok: `Retest queued (${r.effectiveMode}). The result appears here when the scan finishes.` });
                      }}>Request retest</Btn>
                    )}
                  </div>
                  <Msg err={n("findings").err} ok={n("findings").ok} />
                </div>
              )}
            </div>
          ))}
      </Card>
    </main>
  );
}
