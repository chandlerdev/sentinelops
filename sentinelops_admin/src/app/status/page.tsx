"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api, Health } from "@/lib/api";
import { Badge, colors } from "@/components/ui";

// Public status page: confirms the frontend can reach the backend and that the backend can reach its database.
export default function StatusPage() {
  const [health, setHealth] = useState<Health | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    api.health().then(setHealth).catch((e) => setErr(e.message || "Backend unreachable"));
  }, []);

  const ok = health?.status === "UP" && health?.database === "UP";
  return (
    <main className="page" style={{ maxWidth: 600 }}>
      <h1>System status</h1>
      <p className="page-sub">Checks that this page can reach the backend and that the backend can reach its database.</p>
      <div className="card">
        {!health && !err && <p style={{ margin: 0 }}>Checking…</p>}
        {err && <div className="msg err" role="alert" style={{ margin: 0 }}>Backend unreachable: {err}</div>}
        {health && (
          <>
            <p style={{ color: ok ? colors.ok : colors.bad, fontWeight: 650, fontSize: 16, marginTop: 0 }}>
              {ok ? "● All systems operational" : "● Degraded"}
            </p>
            <table style={{ fontSize: 14 }}>
              <tbody>
                <tr><td style={{ color: colors.muted }}>Backend</td><td><Badge text={health.status === "UP" ? "VERIFIED" : "FAILED"} /> {health.status}</td></tr>
                <tr><td style={{ color: colors.muted }}>Database</td><td><Badge text={health.database === "UP" ? "VERIFIED" : "FAILED"} /> {health.database}</td></tr>
                <tr><td style={{ color: colors.muted }}>Service</td><td>{health.service} {health.version}</td></tr>
                <tr><td style={{ color: colors.muted }}>Server time</td><td>{health.time}</td></tr>
              </tbody>
            </table>
          </>
        )}
      </div>
      <p><Link href="/">← Home</Link></p>
    </main>
  );
}
