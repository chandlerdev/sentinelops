"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Badge, Card, colors, fmt, Grid, Msg, useSession } from "@/components/ui";
import { SEV, SEV_COLOR, SeverityBars, Stat } from "@/components/charts";

export default function Dashboard() {
  const { ready } = useSession();
  const [d, setD] = useState<any>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (ready) api.dashboard().then(setD).catch((e) => setErr(e.message));
  }, [ready]);

  if (!ready) return null;
  return (
    <main className="page">
      <h1>Dashboard</h1>
      <p className="page-sub">
        What is still open across your engagements. Scanner results count only after a tester has confirmed them
        (candidates are shown separately).
      </p>
      <Msg err={err} />
      {d && (
        <>
          <Grid min={170}>
            <Stat label="Open findings" value={d.open} />
            <Stat label="Critical + High open" value={d.criticalOrHighOpen} color={d.criticalOrHighOpen ? colors.bad : colors.ok} />
            <Stat label="Fixed, awaiting retest" value={d.awaitingRetest} color={colors.accent} />
            <Stat label="Candidates to review" value={d.candidates} color={colors.warn} />
            <Stat label="Engagements" value={d.engagements} />
          </Grid>
          <Card title="Open findings by severity"><SeverityBars counts={d.openBySeverity} /></Card>
          <Card title="Engagements">
            {d.perEngagement.length === 0 && <p style={{ color: colors.muted, fontSize: 13, margin: 0 }}>None yet.</p>}
            {d.perEngagement.map((s: any) => (
              <div key={s.engagementId} style={{ padding: "10px 0", borderBottom: `1px solid ${colors.border}`, fontSize: 13 }}>
                <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
                  <Link href={`/engagements/${s.engagementId}`} style={{ color: colors.accent, fontWeight: 600 }}>{s.engagementName}</Link>
                  <span style={{ color: colors.muted }}>
                    {s.open} open · {s.awaitingRetest} awaiting retest · {s.resolved} resolved · {s.candidates} candidates ·
                    targets verified {s.verifiedTargets}/{s.targets} · last scan {fmt(s.lastScanAt)}
                  </span>
                  {s.scansRunning > 0 && <Badge text="RUNNING" />}
                </div>
                <div style={{ display: "flex", gap: 8, marginTop: 6 }}>
                  {SEV.filter((x) => s.openBySeverity[x] > 0).map((x) => (
                    <span key={x} style={{ fontSize: 11, color: SEV_COLOR[x], border: `1px solid ${SEV_COLOR[x]}`, borderRadius: 999, padding: "1px 8px" }}>
                      {x.toLowerCase()} {s.openBySeverity[x]}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </Card>
        </>
      )}
    </main>
  );
}
