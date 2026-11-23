"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { colors, fmt, Msg, useSession } from "@/components/ui";

export default function Audit() {
  const { ready } = useSession(["ADMIN", "MANAGER"]);
  const [rows, setRows] = useState<any[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => { if (ready) api.audit(200).then(setRows).catch((e) => setErr(e.message)); }, [ready]);

  if (!ready) return null;
  return (
    <main style={{ maxWidth: 1100, margin: "0 auto", padding: "26px 20px" }}>
      <h1>Audit log</h1>
      <p style={{ color: colors.muted, fontSize: 13 }}>Append-only record of target changes, verifications, authorizations, gate decisions (including refusals) and scans. Newest first.</p>
      <Msg err={err} />
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
        <thead><tr style={{ textAlign: "left", color: colors.muted }}>
          <th style={{ padding: 6 }}>Time</th><th>Actor</th><th>Action</th><th>Entity</th><th>Detail</th>
        </tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id} style={{ borderTop: `1px solid ${colors.border}`, verticalAlign: "top" }}>
              <td style={{ padding: 6, whiteSpace: "nowrap" }}>{fmt(r.createdAt)}</td>
              <td>{r.actor}</td><td>{r.action}</td><td>{r.entity}</td>
              <td style={{ color: colors.muted, wordBreak: "break-word" }}>{r.detail}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </main>
  );
}
