"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Btn, canDecide, Card, colors, Empty, Field, fmt, Grid, Msg, useSession, useValidation } from "@/components/ui";

export default function Clients() {
  const { ready, role } = useSession(["ADMIN", "MANAGER", "TESTER"]);
  const [clients, setClients] = useState<any[]>([]);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);
  const [form, setForm] = useState({ name: "", contact: "", tier: "", compliance: "" });
  const v = useValidation();

  const load = () => api.clients().then(setClients).catch((e) => setLoadErr(e.message));
  useEffect(() => { if (ready) load(); }, [ready]);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setErr(null); setOk(null);
    if (!v.check({
      name: { label: "Name", value: form.name },
      contact: { label: "Contact", value: form.contact, email: true },
    })) return;
    try {
      await api.createClient(form);
      setForm({ name: "", contact: "", tier: "", compliance: "" });
      setOk("Client created.");
      load();
    } catch (e: any) { setErr(e.message); }
  }

  if (!ready) return null;
  const set = (k: string, val: string) => { setForm({ ...form, [k]: val }); v.clear(k); };
  return (
    <main className="page">
      <h1>Clients</h1>
      <p className="page-sub">The organisations whose systems we test.</p>
      <Msg err={loadErr} />
      <div className="card table-wrap" style={{ padding: 8 }}>
        {clients.length === 0 ? <Empty>No clients yet.</Empty> : (
          <table>
            <thead><tr><th>Name</th><th>Contact</th><th>Tier</th><th>Compliance</th><th>Created</th></tr></thead>
            <tbody>
              {clients.map((c) => (
                <tr key={c.id} style={{ borderTop: `1px solid ${colors.border}` }}>
                  <td><b>{c.name}</b></td><td>{c.contact}</td><td>{c.tier || "-"}</td>
                  <td>{c.compliance || "-"}</td><td>{fmt(c.createdAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {canDecide(role) && (
        <Card title="New client">
          <form onSubmit={create} noValidate>
            <Grid>
              <Field label="Name" required error={v.errors.name}><input value={form.name} onChange={(e) => set("name", e.target.value)} /></Field>
              <Field label="Contact" required error={v.errors.contact} hint="Contact e-mail address"><input value={form.contact} onChange={(e) => set("contact", e.target.value)} /></Field>
              <Field label="Tier"><input value={form.tier} onChange={(e) => set("tier", e.target.value)} /></Field>
              <Field label="Compliance"><input value={form.compliance} onChange={(e) => set("compliance", e.target.value)} /></Field>
            </Grid>
            <div style={{ marginTop: 14 }}><Btn type="submit">Create client</Btn></div>
            <Msg err={err} ok={ok} />
          </form>
        </Card>
      )}
    </main>
  );
}
