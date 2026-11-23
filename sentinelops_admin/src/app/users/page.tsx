"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Btn, Card, colors, Field, fieldStyle, fmt, Grid, Msg, useSession } from "@/components/ui";

export default function Users() {
  const { ready } = useSession(["ADMIN"]);
  const [users, setUsers] = useState<any[]>([]);
  const [clients, setClients] = useState<any[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);
  const [form, setForm] = useState({ name: "", email: "", password: "", role: "TESTER", clientId: "" });

  const load = () => {
    api.users().then(setUsers).catch((e) => setErr(e.message));
    api.clients().then(setClients).catch(() => {});
  };
  useEffect(() => { if (ready) load(); }, [ready]);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setErr(null); setOk(null);
    try {
      await api.createUser({ ...form, clientId: form.role === "CLIENT" ? form.clientId : null });
      setOk(`User ${form.email} created.`);
      setForm({ name: "", email: "", password: "", role: "TESTER", clientId: "" });
      load();
    } catch (e: any) { setErr(e.message); }
  }

  if (!ready) return null;
  return (
    <main style={{ maxWidth: 940, margin: "0 auto", padding: "26px 20px" }}>
      <h1>Users</h1>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 14 }}>
        <thead><tr style={{ textAlign: "left", color: colors.muted }}>
          <th style={{ padding: 8 }}>Name</th><th>Email</th><th>Role</th><th>Active</th><th>Created</th>
        </tr></thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.id} style={{ borderTop: `1px solid ${colors.border}` }}>
              <td style={{ padding: 8 }}>{u.name}</td><td>{u.email}</td><td>{u.role}</td>
              <td>{u.active ? "yes" : "no"}</td><td>{fmt(u.createdAt)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <Card title="New user">
        <form onSubmit={create}>
          <Grid>
            <Field label="Name"><input style={fieldStyle} required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field>
            <Field label="Email"><input style={fieldStyle} type="email" required value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></Field>
            <Field label="Password (min 10 characters)"><input style={fieldStyle} type="password" minLength={10} required value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></Field>
            <Field label="Role">
              <select style={fieldStyle} value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
                {["TESTER", "MANAGER", "ADMIN", "CLIENT"].map((r) => <option key={r}>{r}</option>)}
              </select>
            </Field>
            {form.role === "CLIENT" && (
              <Field label="Client">
                <select style={fieldStyle} required value={form.clientId} onChange={(e) => setForm({ ...form, clientId: e.target.value })}>
                  <option value="">Select…</option>
                  {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
                </select>
              </Field>
            )}
          </Grid>
          <div style={{ marginTop: 12 }}><Btn type="submit">Create user</Btn></div>
          <Msg err={err} ok={ok} />
        </form>
      </Card>
    </main>
  );
}
