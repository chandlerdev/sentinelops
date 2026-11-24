"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import { Badge, Btn, canDecide, Card, colors, Empty, Field, fmt, Grid, Msg, useSession, useValidation } from "@/components/ui";

export default function Home() {
  const { ready, role } = useSession();
  const [engagements, setEngagements] = useState<any[]>([]);
  const [clients, setClients] = useState<any[]>([]);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);
  const [form, setForm] = useState({ name: "", clientId: "", environment: "Staging" });
  const v = useValidation();

  function load() {
    api.engagements().then(setEngagements).catch((e) => setLoadErr(e.message));
    api.clients().then(setClients).catch(() => {});
  }
  useEffect(() => { if (ready) load(); }, [ready]);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setErr(null); setOk(null);
    if (!v.check({
      name: { label: "Name", value: form.name },
      clientId: { label: "Client", value: form.clientId },
    })) return;
    try {
      await api.createEngagement(form);
      setForm({ ...form, name: "" });
      setOk("Engagement created.");
      load();
    } catch (e: any) { setErr(e.message); }
  }

  if (!ready) return null;
  const clientName = (id: string) => clients.find((c) => c.id === id)?.name || id;

  return (
    <main className="page">
      <h1>Engagements</h1>
      <p className="page-sub">Authorized security assessments. No target is scanned without verification and a signed authorization.</p>
      <Msg err={loadErr} />

      <div style={{ display: "grid", gap: 12, marginTop: 18 }}>
        {engagements.length === 0 && <Empty>No engagements yet.</Empty>}
        {engagements.map((e) => (
          <Link key={e.id} href={`/engagements/${e.id}`} className="list-card">
            <div style={{ display: "flex", justifyContent: "space-between", gap: 10, alignItems: "center" }}>
              <strong style={{ fontSize: 15 }}>{e.name}</strong><Badge text={e.state} />
            </div>
            <div style={{ color: colors.muted, fontSize: 13, marginTop: 5 }}>
              {clientName(e.clientId)} · {e.environment || "-"} · created {fmt(e.createdAt)}
            </div>
          </Link>
        ))}
      </div>

      {canDecide(role) && (
        <Card title="New engagement">
          <form onSubmit={create} noValidate>
            <Grid>
              <Field label="Name" required error={v.errors.name}>
                <input value={form.name} onChange={(e) => { setForm({ ...form, name: e.target.value }); v.clear("name"); }} />
              </Field>
              <Field label="Client" required error={v.errors.clientId}>
                <select value={form.clientId} onChange={(e) => { setForm({ ...form, clientId: e.target.value }); v.clear("clientId"); }}>
                  <option value="">Select a client…</option>
                  {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
                </select>
              </Field>
              <Field label="Environment">
                <input value={form.environment} onChange={(e) => setForm({ ...form, environment: e.target.value })} />
              </Field>
            </Grid>
            <div style={{ marginTop: 14 }}><Btn type="submit">Create engagement</Btn></div>
            <Msg err={err} ok={ok} />
          </form>
        </Card>
      )}
    </main>
  );
}
