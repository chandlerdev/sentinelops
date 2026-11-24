"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Badge, Btn, Card, colors, Empty, Field, fmt, Grid, Msg, useSession, useValidation } from "@/components/ui";

export default function Users() {
  const { ready } = useSession(["ADMIN"]);
  const [users, setUsers] = useState<any[]>([]);
  const [clients, setClients] = useState<any[]>([]);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);
  const [form, setForm] = useState({ name: "", email: "", password: "", role: "TESTER", clientId: "" });
  const v = useValidation();

  const load = () => {
    api.users().then(setUsers).catch((e) => setLoadErr(e.message));
    api.clients().then(setClients).catch(() => {});
  };
  useEffect(() => { if (ready) load(); }, [ready]);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setErr(null); setOk(null);
    const rules: Record<string, any> = {
      name: { label: "Name", value: form.name },
      email: { label: "Email", value: form.email, email: true },
      password: { label: "Password", value: form.password, min: 10 },
    };
    if (form.role === "CLIENT") rules.clientId = { label: "Client", value: form.clientId };
    if (!v.check(rules)) return;
    try {
      await api.createUser({ ...form, clientId: form.role === "CLIENT" ? form.clientId : null });
      setOk(`User ${form.email} created.`);
      setForm({ name: "", email: "", password: "", role: "TESTER", clientId: "" });
      load();
    } catch (e: any) { setErr(e.message); }
  }

  if (!ready) return null;
  const set = (k: string, val: string) => { setForm({ ...form, [k]: val }); v.clear(k); };
  return (
    <main className="page">
      <h1>Users</h1>
      <p className="page-sub">Accounts that can sign in. Only an administrator can create them.</p>
      <Msg err={loadErr} />
      <div className="card table-wrap" style={{ padding: 8 }}>
        {users.length === 0 ? <Empty>No users.</Empty> : (
          <table>
            <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Active</th><th>Created</th></tr></thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} style={{ borderTop: `1px solid ${colors.border}` }}>
                  <td><b>{u.name}</b></td><td>{u.email}</td><td><Badge text={u.role} /></td>
                  <td>{u.active ? "yes" : "no"}</td><td>{fmt(u.createdAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <Card title="New user">
        <form onSubmit={create} noValidate>
          <Grid>
            <Field label="Name" required error={v.errors.name}><input value={form.name} onChange={(e) => set("name", e.target.value)} /></Field>
            <Field label="Email" required error={v.errors.email}><input type="email" value={form.email} onChange={(e) => set("email", e.target.value)} /></Field>
            <Field label="Password" required error={v.errors.password} hint="At least 10 characters"><input type="password" autoComplete="new-password" value={form.password} onChange={(e) => set("password", e.target.value)} /></Field>
            <Field label="Role">
              <select value={form.role} onChange={(e) => set("role", e.target.value)}>
                {["TESTER", "MANAGER", "ADMIN", "CLIENT"].map((r) => <option key={r}>{r}</option>)}
              </select>
            </Field>
            {form.role === "CLIENT" && (
              <Field label="Client" required error={v.errors.clientId}>
                <select value={form.clientId} onChange={(e) => set("clientId", e.target.value)}>
                  <option value="">Select a client…</option>
                  {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
                </select>
              </Field>
            )}
          </Grid>
          <div style={{ marginTop: 14 }}><Btn type="submit">Create user</Btn></div>
          <Msg err={err} ok={ok} />
        </form>
      </Card>
    </main>
  );
}
