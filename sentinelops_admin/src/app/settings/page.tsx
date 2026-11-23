"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Badge, Btn, Card, colors, Msg, useSession } from "@/components/ui";

export default function Settings() {
  const { ready, role } = useSession(["ADMIN", "MANAGER"]);
  const [active, setActive] = useState<boolean | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => { if (ready) api.settings().then((s) => setActive(s.activeScanningEnabled)).catch((e) => setErr(e.message)); }, [ready]);

  async function toggle() {
    setErr(null);
    try { setActive((await api.setActiveScanning(!active)).activeScanningEnabled); }
    catch (e: any) { setErr(e.message); }
  }

  if (!ready) return null;
  return (
    <main style={{ maxWidth: 760, margin: "0 auto", padding: "26px 20px" }}>
      <h1>Settings</h1>
      <Card title="Active scanning (global switch)">
        <p style={{ color: colors.muted, fontSize: 13, marginTop: 0 }}>
          Active scanning sends intrusive test traffic. It runs only when <b>both</b> this switch is ON and the
          engagement&apos;s authorization explicitly allows it. Off by default; only an administrator can change it.
        </p>
        <p>Current state: {active === null ? "…" : <Badge text={active ? "VERIFIED" : "REJECTED"} />} {active === null ? "" : active ? "ON" : "OFF"}</p>
        {role === "ADMIN"
          ? <Btn kind={active ? "danger" : "primary"} onClick={toggle}>{active ? "Turn OFF" : "Turn ON"}</Btn>
          : <p style={{ color: colors.muted, fontSize: 13 }}>Only an administrator can change this.</p>}
        <Msg err={err} />
      </Card>
    </main>
  );
}
