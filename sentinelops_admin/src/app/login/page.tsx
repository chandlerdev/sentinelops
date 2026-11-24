"use client";

import { useState } from "react";
import { api, setSession } from "@/lib/api";
import { useRouter } from "next/navigation";
import { Btn, Field, Msg, useValidation } from "@/components/ui";

export default function Login() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const v = useValidation();

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    if (!v.check({
      email: { label: "Email", value: email, email: true },
      password: { label: "Password", value: password },
    })) return;
    setBusy(true);
    try {
      const res = await api.login(email.trim(), password);
      setSession(res.token, res.role);
      router.push("/");
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-wrap">
      <div className="auth-card">
        <div className="auth-logo">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M12 3l8 3v6c0 4.5-3.2 8.2-8 9-4.8-.8-8-4.5-8-9V6l8-3z" /><path d="M9 12l2 2 4-4" />
          </svg>
        </div>
        <h1>Sign in to SentinelOps</h1>
        <p className="page-sub" style={{ fontSize: 13 }}>Authorized security assessments. Nothing is scanned without verification and a signed authorization.</p>
        <form onSubmit={submit} noValidate style={{ display: "grid", gap: 16, marginTop: 18 }}>
          <Field label="Email" required error={v.errors.email}>
            <input type="email" autoComplete="username" value={email} placeholder="you@company.com"
                   onChange={(e) => { setEmail(e.target.value); v.clear("email"); }} />
          </Field>
          <Field label="Password" required error={v.errors.password}>
            <input type="password" autoComplete="current-password" value={password}
                   onChange={(e) => { setPassword(e.target.value); v.clear("password"); }} />
          </Field>
          <Btn type="submit" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</Btn>
          <Msg err={err} />
        </form>
      </div>
    </div>
  );
}
