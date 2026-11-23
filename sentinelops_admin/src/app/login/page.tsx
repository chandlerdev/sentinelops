"use client";

import { useState } from "react";
import { api, setSession } from "@/lib/api";
import { useRouter } from "next/navigation";
import { Btn, Field, fieldStyle, Msg } from "@/components/ui";

export default function Login() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr(null); setBusy(true);
    try {
      const res = await api.login(email, password);
      setSession(res.token, res.role);
      router.push("/");
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main style={{ maxWidth: 380, margin: "70px auto", padding: "0 20px" }}>
      <h1 style={{ fontSize: 22 }}>Sign in</h1>
      <form onSubmit={submit} style={{ display: "grid", gap: 14 }}>
        <Field label="Email">
          <input style={fieldStyle} type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </Field>
        <Field label="Password">
          <input style={fieldStyle} type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </Field>
        <Msg err={err} />
        <Btn type="submit" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</Btn>
      </form>
    </main>
  );
}
