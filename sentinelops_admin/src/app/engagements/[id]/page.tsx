"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { SeverityBars, Stat } from "@/components/charts";
import {
  Badge, Btn, canDecide, Card, colors, Field, fieldStyle, fmt, Grid, isStaff, Msg, useSession,
} from "@/components/ui";

const METHODS = ["WEB", "API", "NETWORK", "TLS"];
const toIso = (local: string) => (local ? new Date(local).toISOString() : "");

export default function EngagementDetail({ params }: { params: { id: string } }) {
  const id = params.id;
  const { ready, role } = useSession();
  const [engagement, setEngagement] = useState<any>(null);
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
  const [err, setErr] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);

  // target registration
  const [tForm, setTForm] = useState({ value: "", label: "", lab: false });
  // per-target panel
  const [panel, setPanel] = useState<{ targetId: string; kind: "verify" | "manual" | "gate" | "creds" } | null>(null);
  const [challenge, setChallenge] = useState<any>(null);
  const [manual, setManual] = useState({ approverName: "", approverContact: "", networkAckBy: "", evidenceRef: "", notes: "" });
  const [gate, setGate] = useState({ category: "WEB", mode: "PASSIVE" });
  const [gateResult, setGateResult] = useState<any>(null);
  // authorization form
  const blank = {
    title: "", approverName: "", approverContact: "", emergencyContact: "", evidenceRef: "",
    windowStart: "", windowEnd: "", allowActive: false, allowAuthenticated: false, excluded: "", methods: ["WEB"] as string[], targetIds: [] as string[],
  };
  const [aForm, setAForm] = useState(blank);
  // scan
  const [scan, setScan] = useState({ targetId: "", category: "WEB", mode: "PASSIVE" });

  function load() {
    api.engagement(id).then(setEngagement).catch((e) => setErr(e.message));
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

  async function run(fn: () => Promise<any>, success?: string) {
    setErr(null); setOk(null);
    try { const r = await fn(); if (success) setOk(success); load(); return r; }
    catch (e: any) { setErr(e.message); return null; }
  }

  const targetName = (tid: string) => targets.find((t) => t.id === tid)?.value || tid;
  const canWork = isStaff(role);

  async function register(e: React.FormEvent) {
    e.preventDefault();
    const r = await run(() => api.registerTarget(id, tForm), "Target registered. It is NOT yet verified or authorized.");
    if (r) setTForm({ value: "", label: "", lab: false });
  }

  async function startVerify(t: any, method: string) {
    setPanel({ targetId: t.id, kind: "verify" });
    const r = await run(() => api.startVerification(id, t.id, method));
    if (r) setChallenge(r);
  }
  async function checkNow(t: any) {
    const r = await run(() => api.checkVerification(id, t.id));
    if (r) { setChallenge(r); if (r.status === "VERIFIED") setOk("Ownership verified."); }
  }
  async function submitManual(e: React.FormEvent, t: any) {
    e.preventDefault();
    const r = await run(() => api.manualApproval(id, t.id, manual), "Ownership approval recorded.");
    if (r) setPanel(null);
  }
  async function doGate(t: any) {
    const r = await run(() => api.gateCheck(id, t.id, gate.category, gate.mode));
    if (r) setGateResult(r);
  }

  // ---- credentials / OpenAPI ----
  const [cred, setCred] = useState<any>(null);
  const [credForm, setCredForm] = useState({ name: "Authorization", value: "" });
  const [openApiUrl, setOpenApiUrl] = useState("");
  async function openCreds(t: any) {
    setPanel({ targetId: t.id, kind: "creds" });
    setCred(null); setOpenApiUrl(t.openApiUrl || ""); setCredForm({ name: "Authorization", value: "" });
    try { setCred(await api.credential(id, t.id)); } catch (e: any) { setErr(e.message); }
  }
  async function saveCred(e: React.FormEvent, t: any) {
    e.preventDefault();
    const r = await run(() => api.setCredential(id, t.id, credForm.name, credForm.value), "Credential saved (encrypted). The value cannot be shown again.");
    setCredForm({ ...credForm, value: "" });
    if (r) setCred(await api.credential(id, t.id));
  }
  async function removeCred(t: any) {
    await run(() => api.deleteCredential(id, t.id), "Credential removed.");
    setCred(await api.credential(id, t.id));
  }
  async function saveOpenApi(e: React.FormEvent, t: any) {
    e.preventDefault();
    await run(() => api.setOpenApi(id, t.id, openApiUrl), openApiUrl ? "API definition saved." : "API definition cleared.");
  }

  async function createAuth(e: React.FormEvent) {
    e.preventDefault();
    const payload = {
      title: aForm.title, approverName: aForm.approverName, approverContact: aForm.approverContact,
      emergencyContact: aForm.emergencyContact, evidenceRef: aForm.evidenceRef,
      permittedMethods: aForm.methods, targetIds: aForm.targetIds, allowActive: aForm.allowActive, allowAuthenticated: aForm.allowAuthenticated,
      excludedAssets: aForm.excluded.split(",").map((s) => s.trim()).filter(Boolean),
      windowStart: toIso(aForm.windowStart), windowEnd: toIso(aForm.windowEnd),
    };
    const r = await run(() => api.createAuthorization(id, payload), "Authorization drafted. Submit it for approval.");
    if (r) setAForm(blank);
  }
  const toggle = (list: string[], v: string) => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);

  async function startScan(e: React.FormEvent) {
    e.preventDefault();
    const r = await run(() => api.scan(id, scan));
    if (r) setOk(`Scan queued (${r.effectiveMode}): ${r.scanRunIds.length} run(s). Progress appears under "Scans" below.`);
  }

  const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"];
  const sortedFindings = [...findings].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
  const [openFinding, setOpenFinding] = useState<string | null>(null);

  if (!ready) return null;
  const tableCell: React.CSSProperties = { padding: "8px 6px", verticalAlign: "top" };

  return (
    <main style={{ maxWidth: 1000, margin: "0 auto", padding: "26px 20px" }}>
      <Link href="/" style={{ color: colors.accent, fontSize: 13 }}>← Engagements</Link>
      {engagement && (
        <>
          <h1 style={{ marginBottom: 2 }}>{engagement.name}</h1>
          <p style={{ color: colors.muted, marginTop: 0 }}>
            <Badge text={engagement.state} /> &nbsp;{engagement.environment}
          </p>
        </>
      )}
      <Msg err={err} ok={ok} />

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
          <div style={{ marginTop: 12 }}><SeverityBars counts={dash.summary.openBySeverity} /></div>
        </Card>
      )}

      {/* ---------------- Targets ---------------- */}
      <Card title="1. Targets and ownership verification">
        <p style={{ color: colors.muted, fontSize: 13, marginTop: 0 }}>
          Register a domain, IP or small range (/24 or smaller). Private, loopback, metadata and server addresses are refused.
          Registering a target gives <b>no</b> permission to scan it.
        </p>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
          <thead><tr style={{ textAlign: "left", color: colors.muted }}>
            <th style={tableCell}>Target</th><th>Kind</th><th>Ownership</th><th>Valid until</th><th></th>
          </tr></thead>
          <tbody>
            {targets.map((t) => (
              <tr key={t.id} style={{ borderTop: `1px solid ${colors.border}` }}>
                <td style={tableCell}>{t.value}{t.label ? <span style={{ color: colors.muted }}> · {t.label}</span> : null}</td>
                <td>{t.kind}</td><td><Badge text={t.status} /></td><td>{fmt(t.verificationExpiresAt)}</td>
                <td style={{ textAlign: "right" }}>
                  {canWork && t.status !== "LAB" && t.kind === "DOMAIN" && (
                    <>
                      <Btn small kind="ghost" onClick={() => startVerify(t, "DNS_TXT")}>Verify via DNS</Btn>
                      <Btn small kind="ghost" onClick={() => startVerify(t, "HTTP_FILE")}>Verify via file</Btn>
                    </>
                  )}
                  {canDecide(role) && t.kind !== "DOMAIN" && t.status !== "LAB" && (
                    <Btn small kind="ghost" onClick={() => setPanel({ targetId: t.id, kind: "manual" })}>Record owner approval</Btn>
                  )}
                  {canWork && <Btn small kind="ghost" onClick={() => { setGateResult(null); setPanel({ targetId: t.id, kind: "gate" }); }}>Gate check</Btn>}
                  {canWork && t.kind !== "CIDR" && <Btn small kind="ghost" onClick={() => openCreds(t)}>Login &amp; API</Btn>}
                </td>
              </tr>
            ))}
            {targets.length === 0 && <tr><td colSpan={5} style={{ ...tableCell, color: colors.muted }}>No targets yet.</td></tr>}
          </tbody>
        </table>

        {panel && (() => {
          const t = targets.find((x) => x.id === panel.targetId);
          if (!t) return null;
          return (
            <div style={{ marginTop: 14, padding: 14, border: `1px dashed ${colors.border}`, borderRadius: 10 }}>
              <strong style={{ fontSize: 13 }}>{t.value}</strong>
              {panel.kind === "verify" && challenge && (
                <div style={{ fontSize: 13, marginTop: 8 }}>
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
                  <Btn small kind="ghost" onClick={() => { setPanel(null); setChallenge(null); }}>Close</Btn>
                </div>
              )}
              {panel.kind === "manual" && (
                <form onSubmit={(e) => submitManual(e, t)} style={{ marginTop: 8 }}>
                  <Grid min={200}>
                    <Field label="System owner (name)"><input style={fieldStyle} required value={manual.approverName} onChange={(e) => setManual({ ...manual, approverName: e.target.value })} /></Field>
                    <Field label="Owner contact"><input style={fieldStyle} required value={manual.approverContact} onChange={(e) => setManual({ ...manual, approverContact: e.target.value })} /></Field>
                    <Field label="Network team acknowledged by"><input style={fieldStyle} required value={manual.networkAckBy} onChange={(e) => setManual({ ...manual, networkAckBy: e.target.value })} /></Field>
                    <Field label="Evidence reference (ticket / e-mail id)"><input style={fieldStyle} required value={manual.evidenceRef} onChange={(e) => setManual({ ...manual, evidenceRef: e.target.value })} /></Field>
                  </Grid>
                  <div style={{ marginTop: 10 }}>
                    <Btn type="submit" small>Record approval</Btn>
                    <Btn small kind="ghost" onClick={() => setPanel(null)}>Cancel</Btn>
                  </div>
                </form>
              )}
              {panel.kind === "creds" && (
                <div style={{ marginTop: 8, fontSize: 13 }}>
                  <p style={{ color: colors.muted, marginTop: 0 }}>
                    <b>Authenticated scan.</b> One header (for example <code>Authorization: Bearer …</code> or a <code>Cookie</code>) that the
                    client gave us for a <b>test account</b>. It is stored encrypted, can never be read back, and is used only when a signed
                    authorization allows authenticated testing. Use a low-privilege test account, never a real admin.
                  </p>
                  <div style={{ marginBottom: 8 }}>
                    Current: {cred?.present ? <b>{cred.headerName} (value hidden), set by {cred.createdBy}</b> : "none"}
                    {cred?.present && <Btn small kind="ghost" onClick={() => removeCred(t)}>Remove</Btn>}
                  </div>
                  <form onSubmit={(e) => saveCred(e, t)}>
                    <Grid min={200}>
                      <Field label="Header name"><input style={fieldStyle} required value={credForm.name} onChange={(e) => setCredForm({ ...credForm, name: e.target.value })} /></Field>
                      <Field label="Header value"><input style={fieldStyle} type="password" autoComplete="off" required value={credForm.value} onChange={(e) => setCredForm({ ...credForm, value: e.target.value })} /></Field>
                    </Grid>
                    <div style={{ marginTop: 8 }}><Btn type="submit" small>Save credential</Btn></div>
                  </form>
                  <hr style={{ border: 0, borderTop: `1px solid ${colors.border}`, margin: "14px 0" }} />
                  <p style={{ color: colors.muted, marginTop: 0 }}>
                    <b>API definition (OpenAPI / Swagger).</b> Must be on this target&apos;s own host. Used by the ACTIVE API scan only
                    (ZAP API scan); the passive API check does not need it.
                  </p>
                  <form onSubmit={(e) => saveOpenApi(e, t)} style={{ display: "flex", gap: 8 }}>
                    <input style={fieldStyle} placeholder={`https://${t.value}/openapi.json`} value={openApiUrl} onChange={(e) => setOpenApiUrl(e.target.value)} />
                    <Btn type="submit" small>Save</Btn>
                  </form>
                  <div style={{ marginTop: 8 }}><Btn small kind="ghost" onClick={() => setPanel(null)}>Close</Btn></div>
                </div>
              )}
              {panel.kind === "gate" && (
                <div style={{ marginTop: 8, fontSize: 13 }}>
                  <p style={{ color: colors.muted, marginTop: 0 }}>Dry run: asks the authorization gate exactly what a real scan would ask. Nothing is scanned.</p>
                  <select style={{ ...fieldStyle, width: 140, marginRight: 8 }} value={gate.category} onChange={(e) => setGate({ ...gate, category: e.target.value })}>
                    {METHODS.map((m) => <option key={m}>{m}</option>)}
                  </select>
                  <select style={{ ...fieldStyle, width: 140, marginRight: 8 }} value={gate.mode} onChange={(e) => setGate({ ...gate, mode: e.target.value })}>
                    <option>PASSIVE</option><option>ACTIVE</option>
                  </select>
                  <Btn small onClick={() => doGate(t)}>Check gate</Btn>
                  <Btn small kind="ghost" onClick={() => setPanel(null)}>Close</Btn>
                  {gateResult && (
                    <p style={{ color: gateResult.allowed ? colors.ok : colors.bad }}>
                      {gateResult.allowed
                        ? `ALLOWED (${gateResult.effectiveMode}). Resolved: ${gateResult.resolvedAddresses.join(", ")}`
                        : `DENIED: ${gateResult.reason}`}
                    </p>
                  )}
                </div>
              )}
            </div>
          );
        })()}

        {canWork && (
          <form onSubmit={register} style={{ marginTop: 16 }}>
            <Grid min={200}>
              <Field label="Domain, URL, IP or CIDR"><input style={fieldStyle} required value={tForm.value} placeholder="app.example.com" onChange={(e) => setTForm({ ...tForm, value: e.target.value })} /></Field>
              <Field label="Label (optional)"><input style={fieldStyle} value={tForm.label} onChange={(e) => setTForm({ ...tForm, label: e.target.value })} /></Field>
              {role === "ADMIN" && (
                <Field label="Lab asset (our own practice target)">
                  <input type="checkbox" checked={tForm.lab} onChange={(e) => setTForm({ ...tForm, lab: e.target.checked })} />
                </Field>
              )}
            </Grid>
            <div style={{ marginTop: 10 }}><Btn type="submit">Register target</Btn></div>
          </form>
        )}
      </Card>

      {/* ---------------- Authorizations ---------------- */}
      <Card title="2. Written authorizations">
        <p style={{ color: colors.muted, fontSize: 13, marginTop: 0 }}>
          Ownership proof is not permission. A scan needs a signed authorization covering the target, the method and the time window.
          Flow: draft → submit → approved by a manager/admin.
        </p>
        {auths.length === 0 && <p style={{ color: colors.muted, fontSize: 13 }}>No authorizations yet.</p>}
        {auths.map((a) => (
          <div key={a.id} style={{ borderTop: `1px solid ${colors.border}`, padding: "12px 0", fontSize: 13 }}>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <strong>{a.title}</strong><Badge text={a.status} />
            </div>
            <div style={{ color: colors.muted, marginTop: 4 }}>
              Methods: {a.permittedMethods.join(", ")} · Active: {a.allowActive ? "allowed" : "no"} · Authenticated: {a.allowAuthenticated ? "allowed" : "no"} · Window: {fmt(a.windowStart)} → {fmt(a.windowEnd)}<br />
              Targets: {a.targetIds.map(targetName).join(", ")}{a.excludedAssets.length ? ` · Excluded: ${a.excludedAssets.join(", ")}` : ""}<br />
              Approver: {a.approverName} ({a.approverContact}) · Emergency: {a.emergencyContact} · Evidence: {a.evidenceRef}<br />
              Requested by {a.requestedBy}{a.approvedBy ? ` · decided by ${a.approvedBy}` : ""}{a.decisionNote ? ` · "${a.decisionNote}"` : ""}
            </div>
            <div style={{ marginTop: 8 }}>
              {a.status === "DRAFT" && canWork && <Btn small onClick={() => run(() => api.submitAuthorization(a.id), "Submitted for approval.")}>Submit for approval</Btn>}
              {a.status === "PENDING_APPROVAL" && canDecide(role) && (
                <>
                  <Btn small onClick={() => run(() => api.approveAuthorization(a.id, "Approved"), "Authorization approved.")}>Approve</Btn>
                  <Btn small kind="danger" onClick={() => run(() => api.rejectAuthorization(a.id, "Rejected"), "Authorization rejected.")}>Reject</Btn>
                </>
              )}
              {a.status === "SIGNED" && canDecide(role) && (
                <Btn small kind="danger" onClick={() => run(() => api.revokeAuthorization(a.id, "Revoked"), "Authorization revoked.")}>Revoke</Btn>
              )}
            </div>
          </div>
        ))}

        {canWork && (
          <form onSubmit={createAuth} style={{ marginTop: 14, borderTop: `1px solid ${colors.border}`, paddingTop: 14 }}>
            <strong style={{ fontSize: 13 }}>New authorization</strong>
            <Grid min={210}>
              <Field label="Title"><input style={fieldStyle} required value={aForm.title} onChange={(e) => setAForm({ ...aForm, title: e.target.value })} /></Field>
              <Field label="Client approver (name)"><input style={fieldStyle} required value={aForm.approverName} onChange={(e) => setAForm({ ...aForm, approverName: e.target.value })} /></Field>
              <Field label="Approver contact"><input style={fieldStyle} required value={aForm.approverContact} onChange={(e) => setAForm({ ...aForm, approverContact: e.target.value })} /></Field>
              <Field label="Emergency contact"><input style={fieldStyle} required value={aForm.emergencyContact} onChange={(e) => setAForm({ ...aForm, emergencyContact: e.target.value })} /></Field>
              <Field label="Evidence of approval (reference)"><input style={fieldStyle} required value={aForm.evidenceRef} onChange={(e) => setAForm({ ...aForm, evidenceRef: e.target.value })} /></Field>
              <Field label="Testing starts"><input style={fieldStyle} type="datetime-local" required value={aForm.windowStart} onChange={(e) => setAForm({ ...aForm, windowStart: e.target.value })} /></Field>
              <Field label="Testing ends"><input style={fieldStyle} type="datetime-local" required value={aForm.windowEnd} onChange={(e) => setAForm({ ...aForm, windowEnd: e.target.value })} /></Field>
              <Field label="Excluded assets (comma separated)"><input style={fieldStyle} value={aForm.excluded} onChange={(e) => setAForm({ ...aForm, excluded: e.target.value })} /></Field>
            </Grid>
            <div style={{ marginTop: 10, fontSize: 13 }}>
              Permitted methods:{" "}
              {METHODS.map((m) => (
                <label key={m} style={{ marginRight: 14 }}>
                  <input type="checkbox" checked={aForm.methods.includes(m)} onChange={() => setAForm({ ...aForm, methods: toggle(aForm.methods, m) })} /> {m}
                </label>
              ))}
              <label style={{ marginLeft: 10 }}>
                <input type="checkbox" checked={aForm.allowActive} onChange={(e) => setAForm({ ...aForm, allowActive: e.target.checked })} /> allow ACTIVE testing
              </label>
              <label style={{ marginLeft: 10 }}>
                <input type="checkbox" checked={aForm.allowAuthenticated} onChange={(e) => setAForm({ ...aForm, allowAuthenticated: e.target.checked })} /> allow AUTHENTICATED testing (use a login/token the client gives us)
              </label>
            </div>
            <div style={{ marginTop: 10, fontSize: 13 }}>
              Targets in scope:{" "}
              {targets.length === 0 && <span style={{ color: colors.muted }}>register a target first</span>}
              {targets.map((t) => (
                <label key={t.id} style={{ marginRight: 14 }}>
                  <input type="checkbox" checked={aForm.targetIds.includes(t.id)} onChange={() => setAForm({ ...aForm, targetIds: toggle(aForm.targetIds, t.id) })} /> {t.value}
                </label>
              ))}
            </div>
            <div style={{ marginTop: 12 }}><Btn type="submit">Create draft</Btn></div>
          </form>
        )}
      </Card>

      {/* ---------------- Scan ---------------- */}
      {canWork && (
        <Card title="3. Start a scan">
          <p style={{ color: colors.muted, fontSize: 13, marginTop: 0 }}>
            The gate must pass first. A permitted request is queued (one run per tool) and the background worker runs each tool in
            its own container. WEB = Nuclei + ZAP, API = Nuclei, TLS = testssl, NETWORK = Nmap. Only what the tools actually report is recorded.
          </p>
          <form onSubmit={startScan} style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <select style={{ ...fieldStyle, width: 240 }} required value={scan.targetId} onChange={(e) => setScan({ ...scan, targetId: e.target.value })}>
              <option value="">Select target…</option>
              {targets.map((t) => <option key={t.id} value={t.id}>{t.value}</option>)}
            </select>
            <select style={{ ...fieldStyle, width: 120 }} value={scan.category} onChange={(e) => setScan({ ...scan, category: e.target.value })}>
              {METHODS.map((m) => <option key={m}>{m}</option>)}
            </select>
            <select style={{ ...fieldStyle, width: 120 }} value={scan.mode} onChange={(e) => setScan({ ...scan, mode: e.target.value })}>
              <option>PASSIVE</option><option>ACTIVE</option>
            </select>
            <Btn type="submit">Request scan</Btn>
          </form>
        </Card>
      )}

      {/* ---------------- Scans ---------------- */}
      <Card title="Scans" right={<Btn kind="ghost" small onClick={load}>Refresh</Btn>}>
        {runs.length === 0
          ? <p style={{ color: colors.muted, fontSize: 13, margin: 0 }}>No scans yet.</p>
          : runs.map((r) => (
            <div key={r.id} style={{ fontSize: 13, padding: "8px 0", borderBottom: "1px solid #eee" }}>
              <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                <Badge text={r.status} />
                <b>{r.tool}</b> · {r.category} · {r.mode}{r.purpose && r.purpose !== "SCAN" ? ` · ${r.purpose.toLowerCase()}` : ""} · {r.targetHost}
                <span style={{ color: colors.muted }}>
                  started {fmt(r.startedAt)} · ended {fmt(r.endedAt)}{r.status === "COMPLETED" ? ` · ${r.findingCount} finding(s)` : ""}
                </span>
                {canWork && (r.status === "QUEUED" || r.status === "RUNNING") && (
                  <Btn kind="ghost" small onClick={() => run(() => api.stopScan(r.id), "Scan stopped.")}>Stop</Btn>
                )}
              </div>
              {r.error && <div style={{ color: "#b42318", marginTop: 4 }}>{r.error}</div>}
            </div>
          ))}
      </Card>

      {/* ---------------- Schedules ---------------- */}
      {canWork && (
        <Card title="Recurring scans">
          <p style={{ color: colors.muted, fontSize: 13, marginTop: 0 }}>
            A schedule only asks for a scan on time. Every run still passes the full gate (verified ownership, signed
            authorization, window, method, fresh DNS). After 3 refusals in a row it switches itself off.
          </p>
          {scheds.map((s) => (
            <div key={s.id} style={{ fontSize: 13, padding: "6px 0", borderBottom: `1px solid ${colors.border}` }}>
              <b>{targetName(s.targetId)}</b> · {s.category} · {s.mode} · every {s.intervalDays} day(s) · next {fmt(s.nextRunAt)}{" "}
              {s.enabled ? <Badge text="COMPLETED" /> : <Badge text="STOPPED" />}
              <span style={{ marginLeft: 8 }}>
                <Btn small kind="ghost" onClick={() => run(() => api.enableSchedule(s.id, !s.enabled))}>{s.enabled ? "Pause" : "Resume"}</Btn>
                <Btn small kind="ghost" onClick={() => run(() => api.deleteSchedule(s.id), "Schedule deleted.")}>Delete</Btn>
              </span>
              {s.lastResult && <div style={{ color: colors.muted }}>Last: {s.lastResult}</div>}
            </div>
          ))}
          <form onSubmit={(e) => { e.preventDefault(); run(() => api.createSchedule(id, { ...sForm, intervalDays: Number(sForm.intervalDays) }), "Schedule created. First run in about 10 minutes."); }}
                style={{ display: "flex", gap: 10, flexWrap: "wrap", marginTop: 10 }}>
            <select style={{ ...fieldStyle, width: 220 }} required value={sForm.targetId} onChange={(e) => setSForm({ ...sForm, targetId: e.target.value })}>
              <option value="">Select target…</option>
              {targets.map((t) => <option key={t.id} value={t.id}>{t.value}</option>)}
            </select>
            <select style={{ ...fieldStyle, width: 110 }} value={sForm.category} onChange={(e) => setSForm({ ...sForm, category: e.target.value })}>
              {METHODS.map((m) => <option key={m}>{m}</option>)}
            </select>
            <select style={{ ...fieldStyle, width: 110 }} value={sForm.mode} onChange={(e) => setSForm({ ...sForm, mode: e.target.value })}>
              <option>PASSIVE</option><option>ACTIVE</option>
            </select>
            <input style={{ ...fieldStyle, width: 90 }} type="number" min={1} max={365} value={sForm.intervalDays}
                   onChange={(e) => setSForm({ ...sForm, intervalDays: Number(e.target.value) })} title="Repeat every N days" />
            <Btn type="submit">Add schedule</Btn>
          </form>
        </Card>
      )}

      {/* ---------------- Findings ---------------- */}
      <Card title={`Findings (${findings.length})`}
            right={
              <span>
                <Btn small kind="ghost" onClick={() => run(() => api.downloadReport(id, false), "Report downloaded (confirmed findings only).")}>PDF report</Btn>
                {canWork && <Btn small kind="ghost" onClick={() => run(() => api.downloadReport(id, true), "Draft report downloaded, including UNCONFIRMED findings.")}>Draft incl. candidates</Btn>}
              </span>
            }>
        <p style={{ color: colors.muted, fontSize: 12, marginTop: 0 }}>
          {canWork
            ? <>Scanner output is a <b>candidate</b> until you confirm it; clients only see confirmed findings. The same issue found again is not duplicated.
                After a fix is reported, <b>Request retest</b> re-runs only the tool that found it.</>
            : <>Reported issues with how to fix them. Mark an issue <b>In progress</b> or <b>Fixed</b> when you act on it; a tester will re-check it.</>}
        </p>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 8 }}>
          <select style={{ ...fieldStyle, width: 150 }} value={fFilter.severity || ""} onChange={(e) => setFFilter({ ...fFilter, severity: e.target.value || undefined })}>
            <option value="">All severities</option>
            {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"].map((s) => <option key={s}>{s}</option>)}
          </select>
          <select style={{ ...fieldStyle, width: 160 }} value={fFilter.status || ""} onChange={(e) => setFFilter({ ...fFilter, status: e.target.value || undefined })}>
            <option value="">All statuses</option>
            {["OPEN", "IN_PROGRESS", "FIXED", "RETEST_PASS", "RETEST_FAIL", "CLOSED", "FALSE_POSITIVE"].map((s) => <option key={s}>{s}</option>)}
          </select>
          <select style={{ ...fieldStyle, width: 130 }} value={fFilter.tool || ""} onChange={(e) => setFFilter({ ...fFilter, tool: e.target.value || undefined })}>
            <option value="">All tools</option>
            {["nuclei", "zap", "zap-api", "testssl", "nmap"].map((s) => <option key={s}>{s}</option>)}
          </select>
        </div>
        {findings.length === 0
          ? <p style={{ color: colors.muted, fontSize: 13, margin: 0 }}>No findings.</p>
          : findings.map((f) => (
            <div key={f.id} style={{ fontSize: 13, padding: "8px 0", borderBottom: `1px solid ${colors.border}` }}>
              <div style={{ display: "flex", gap: 10, alignItems: "center", cursor: "pointer", flexWrap: "wrap" }}
                   onClick={async () => {
                     if (openFinding === f.id) { setOpenFinding(null); setFDetail(null); return; }
                     setOpenFinding(f.id); setNote("");
                     try { setFDetail(await api.finding(f.id)); } catch { setFDetail(null); }
                   }}>
                <Badge text={f.severity} />
                <Badge text={f.status} />
                {!f.validated && <span style={{ fontSize: 11, color: colors.warn }}>UNCONFIRMED</span>}
                <b>{f.title}</b>
                <span style={{ color: colors.muted }}>{f.tool} · last seen {fmt(f.lastSeenAt)}</span>
              </div>
              {openFinding === f.id && (
                <div style={{ marginTop: 8, paddingLeft: 4, lineHeight: 1.55 }}>
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
                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 8, alignItems: "center" }}>
                    <input style={{ ...fieldStyle, width: 260 }} placeholder="Note (optional)" value={note} onChange={(e) => setNote(e.target.value)} />
                    {canWork && !f.validated && f.status !== "FALSE_POSITIVE" && (
                      <>
                        <Btn small onClick={() => run(() => api.validateFinding(f.id, true, note), "Confirmed. The client can now see it.")}>Confirm</Btn>
                        <Btn small kind="ghost" onClick={() => run(() => api.validateFinding(f.id, false, note), "Dismissed as a false positive.")}>False positive</Btn>
                      </>
                    )}
                    {(canWork ? f.validated || true : f.validated) && [
                      f.status === "OPEN" || f.status === "RETEST_FAIL" ? ["IN_PROGRESS", "Start fixing"] : null,
                      f.status === "OPEN" || f.status === "IN_PROGRESS" || f.status === "RETEST_FAIL" ? ["FIXED", "Mark fixed"] : null,
                      canWork && f.status === "RETEST_PASS" ? ["CLOSED", "Close"] : null,
                      canWork && (f.status === "CLOSED" || f.status === "FALSE_POSITIVE" || f.status === "FIXED") ? ["OPEN", "Reopen"] : null,
                    ].filter(Boolean).map((x: any) => (
                      <Btn key={x[0]} small kind="ghost" onClick={() => run(() => api.setFindingStatus(f.id, x[0], note), `Status: ${x[0]}`)}>{x[1]}</Btn>
                    ))}
                    {canWork && f.status === "FIXED" && (
                      <Btn small onClick={async () => {
                        const r = await run(() => api.retestFinding(f.id));
                        if (r) setOk(`Retest queued (${r.effectiveMode}). The result appears here when the scan finishes.`);
                      }}>Request retest</Btn>
                    )}
                  </div>
                </div>
              )}
            </div>
          ))}
      </Card>
    </main>
  );
}
