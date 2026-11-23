"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api, Health } from "@/lib/api";

// Public status page: confirms the frontend can reach the backend and that the backend can reach its database.
export default function StatusPage() {
  const [health, setHealth] = useState<Health | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    api.health().then(setHealth).catch((e) => setErr(e.message || "Backend unreachable"));
  }, []);

  const ok = health?.status === "UP" && health?.database === "UP";
  return (
    <main style={{ maxWidth: 560, margin: "0 auto", padding: "40px 20px" }}>
      <h1 style={{ letterSpacing: "-0.01em" }}>System status</h1>
      <div style={{ padding: 16, borderRadius: 10, background: "#171a21", border: "1px solid #2a2f3a" }}>
        {!health && !err && <p>Checking…</p>}
        {err && <p style={{ color: "#f85149" }}>Backend unreachable: {err}</p>}
        {health && (
          <>
            <p style={{ color: ok ? "#3fb950" : "#f85149", fontWeight: 600 }}>
              {ok ? "All systems operational" : "Degraded"}
            </p>
            <table style={{ width: "100%", fontSize: 14 }}>
              <tbody>
                <tr><td>Backend</td><td>{health.status}</td></tr>
                <tr><td>Database</td><td>{health.database}</td></tr>
                <tr><td>Service</td><td>{health.service} {health.version}</td></tr>
                <tr><td>Server time</td><td>{health.time}</td></tr>
              </tbody>
            </table>
          </>
        )}
      </div>
      <p><Link href="/" style={{ color: "#5b8cff" }}>← Home</Link></p>
    </main>
  );
}
