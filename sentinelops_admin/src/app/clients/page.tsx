"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Btn, canDecide, Card, colors, Field, fieldStyle, fmt, Grid, Msg, useSession } from "@/components/ui";

export default function Clients() {
  const { ready, role } = useSession(["ADMIN", "MANAGER", "TESTER"]);
  const [clients, setClients] = useState<any[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [form, setForm] = useState({ name: "", contact: "", tier: "", compliance: "" });

  const load = () => api.clients().then(setClients).catch((e) => setErr(e.message));
  useEffect(() => { if (ready) load(); }, [ready]);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    try {
      await api.createClient(form);
      setForm({ name: "", contact: "", tier: "", compliance: "" });
      load();
    } catch (e: any) { setErr(e.message); }
  }

  if (!ready) return null;
  return (
    <main style={{ maxWidth: 940, margin: "0 auto", padding: "26px 20px" }}>
      <h1>Clients</h1>
      <Msg err={err} />
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 14 }}>
        <thead><tr style={{ textAlign: "left", color: colors.muted }}>
          <th style={{ padding: 8 }}>Name</th><th>Contact</th><th>Tier</th><th>Compliance</th><th>Created</th>
        </tr></thead>
        <tbody>
          {clients.map((c) => (
            <tr key={c.id} style={{ borderTop: `1px solid ${colors.border}` }}>
              <td style={{ padding: 8 }}>{c.name}</td><td>{c.contact}</td><td>{c.tier || "-"}</td>
              <td>{c.compliance || "-"}</td><td>{fmt(c.createdAt)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {canDecide(role) && (
        <Card title="New client">
          <form onSubmit={create}>
            <Grid>
              <Field label="Name"><input style={fieldStyle} required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field>
              <Field label="Contact (email)"><input style={fieldStyle} required value={form.contact} onChange={(e) => setForm({ ...form, contact: e.target.value })} /></Field>
              <Field label="Tier"><input style={fieldStyle} value={form.tier} onChange={(e) => setForm({ ...form, tier: e.target.value })} /></Field>
              <Field label="Compliance"><input style={fieldStyle} value={form.compliance} onChange={(e) => setForm({ ...form, compliance: e.target.value })} /></Field>
            </Grid>
            <div style={{ marginTop: 12 }}><Btn type="submit">Create client</Btn></div>
          </form>
        </Card>
      )}
    </main>
  );
}
