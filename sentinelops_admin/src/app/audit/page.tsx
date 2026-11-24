"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { colors, Empty, fmt, Msg, useSession } from "@/components/ui";

export default function Audit() {
  const { ready } = useSession(["ADMIN", "MANAGER"]);
  const [rows, setRows] = useState<any[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => { if (ready) api.audit(200).then(setRows).catch((e) => setErr(e.message)); }, [ready]);

  if (!ready) return null;
  return (
    <main className="page" style={{ maxWidth: 1180 }}>
      <h1>Audit log</h1>
      <p className="page-sub">Append-only record of target changes, verifications, authorizations, gate decisions (including refusals) and scans. Newest first.</p>
      <Msg err={err} />
      <div className="card table-wrap" style={{ padding: 8 }}>
        {rows.length === 0 ? <Empty>No entries yet.</Empty> : (
          <table style={{ fontSize: 13 }}>
            <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Entity</th><th>Detail</th></tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} style={{ borderTop: `1px solid ${colors.border}`, verticalAlign: "top" }}>
                  <td style={{ whiteSpace: "nowrap" }}>{fmt(r.createdAt)}</td>
                  <td>{r.actor}</td><td><code>{r.action}</code></td><td>{r.entity}</td>
                  <td style={{ color: colors.muted, wordBreak: "break-word" }}>{r.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </main>
  );
}
