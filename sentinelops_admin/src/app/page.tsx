"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import { Badge, Btn, canDecide, Card, colors, Field, fieldStyle, fmt, Grid, Msg, useSession } from "@/components/ui";

export default function Home() {
  const { ready, role } = useSession();
  const [engagements, setEngagements] = useState<any[]>([]);
  const [clients, setClients] = useState<any[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [form, setForm] = useState({ name: "", clientId: "", environment: "Staging" });

  function load() {
    api.engagements().then(setEngagements).catch((e) => setErr(e.message));
    api.clients().then(setClients).catch(() => {});
  }
  useEffect(() => { if (ready) load(); }, [ready]);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    try {
      await api.createEngagement(form);
      setForm({ ...form, name: "" });
      load();
    } catch (e: any) { setErr(e.message); }
  }

  if (!ready) return null;
  const clientName = (id: string) => clients.find((c) => c.id === id)?.name || id;

  return (
    <main style={{ maxWidth: 940, margin: "0 auto", padding: "26px 20px" }}>
      <h1 style={{ marginBottom: 2 }}>Engagements</h1>
      <p style={{ color: colors.muted, marginTop: 0 }}>Authorized security assessments. No target is scanned without verification and a signed authorization.</p>
      <Msg err={err} />

      <div style={{ display: "grid", gap: 10, marginTop: 14 }}>
        {engagements.length === 0 && <p style={{ color: colors.muted }}>No engagements yet.</p>}
        {engagements.map((e) => (
          <Link key={e.id} href={`/engagements/${e.id}`} style={{
            display: "block", padding: 16, borderRadius: 10, textDecoration: "none",
            background: colors.panel, border: `1px solid ${colors.border}`, color: colors.text,
          }}>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <strong>{e.name}</strong><Badge text={e.state} />
            </div>
            <div style={{ color: colors.muted, fontSize: 13, marginTop: 4 }}>
              {clientName(e.clientId)} · {e.environment || "-"} · created {fmt(e.createdAt)}
            </div>
          </Link>
        ))}
      </div>

      {canDecide(role) && (
        <Card title="New engagement">
          <form onSubmit={create}>
            <Grid>
              <Field label="Name"><input style={fieldStyle} value={form.name} required
                onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field>
              <Field label="Client">
                <select style={fieldStyle} value={form.clientId} required onChange={(e) => setForm({ ...form, clientId: e.target.value })}>
                  <option value="">Select a client…</option>
                  {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
                </select>
              </Field>
              <Field label="Environment"><input style={fieldStyle} value={form.environment}
                onChange={(e) => setForm({ ...form, environment: e.target.value })} /></Field>
            </Grid>
            <div style={{ marginTop: 12 }}><Btn type="submit">Create engagement</Btn></div>
          </form>
        </Card>
      )}
    </main>
  );
}
