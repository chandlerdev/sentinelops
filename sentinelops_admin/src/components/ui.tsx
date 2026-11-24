"use client";

import React, { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { getRole, getToken, Role } from "@/lib/api";

// Colours are CSS variables (see app/globals.css) so the dark/light theme switch reaches inline styles too.
export const colors = {
  bg: "var(--bg-soft)", panel: "var(--panel)", border: "var(--border)", text: "var(--text)", muted: "var(--muted)",
  accent: "var(--accent)", ok: "var(--ok)", warn: "var(--warn)", bad: "var(--bad)", orange: "var(--orange)",
};

// Inputs are styled globally; this stays so existing `{ ...fieldStyle, width: 140 }` overrides keep working.
export const fieldStyle: React.CSSProperties = {};

export function Card({ title, children, right, step }: {
  title?: string; children: React.ReactNode; right?: React.ReactNode; step?: number;
}) {
  return (
    <section className="card">
      {(title || right) && (
        <div className="card-head">
          <h2 className="card-title">
            {step !== undefined && <span className="step">{step}</span>}
            {title}
          </h2>
          {right}
        </div>
      )}
      {children}
    </section>
  );
}

export function Btn({ children, onClick, kind = "primary", disabled, type = "button", small }: {
  children: React.ReactNode; onClick?: () => void; kind?: "primary" | "ghost" | "danger";
  disabled?: boolean; type?: "button" | "submit"; small?: boolean;
}) {
  return (
    <button type={type} onClick={onClick} disabled={disabled} className={`btn ${kind}${small ? " small" : ""}`}>
      {children}
    </button>
  );
}

/** A labelled input. `error` shows "<name> is required"-style text right under the field. */
export function Field({ label, children, error, required, hint }: {
  label: string; children: React.ReactNode; error?: string | null; required?: boolean; hint?: string;
}) {
  return (
    <label className={`field${error ? " has-error" : ""}`}>
      <span className="label-text">{label}{required && <span className="req" aria-hidden="true">*</span>}</span>
      {children}
      {hint && !error && <span className="hint">{hint}</span>}
      {error && <div className="field-error" role="alert">{error}</div>}
    </label>
  );
}

export function Grid({ children, min = 220 }: { children: React.ReactNode; min?: number }) {
  return <div style={{ display: "grid", gridTemplateColumns: `repeat(auto-fit, minmax(${min}px, 1fr))`, gap: 14 }}>{children}</div>;
}

const badgeColor: Record<string, string> = {
  VERIFIED: colors.ok, SIGNED: colors.ok, LAB: colors.accent, COMPLETED: colors.ok, PASSED: colors.ok,
  UNVERIFIED: colors.muted, DRAFT: colors.muted, EXPIRED: colors.warn, PENDING: colors.warn,
  CRITICAL: colors.bad, HIGH: colors.orange, MEDIUM: colors.warn, LOW: colors.accent, INFORMATIONAL: colors.muted,
  OPEN: colors.warn, IN_PROGRESS: colors.accent, FIXED: colors.accent, RETEST_PASS: colors.ok, RETEST_FAIL: colors.bad,
  CLOSED: colors.ok, FALSE_POSITIVE: colors.muted, QUEUED: colors.muted, RUNNING: colors.accent, STOPPED: colors.muted,
  PENDING_APPROVAL: colors.warn, REJECTED: colors.bad, REVOKED: colors.bad, FAILED: colors.bad,
  AWAITING_AUTHORIZATION: colors.warn,
};
export function Badge({ text }: { text: string }) {
  const c = badgeColor[text] || colors.muted;
  return (
    <span className="badge" style={{ color: c, borderColor: `color-mix(in srgb, ${c} 55%, transparent)`, background: `color-mix(in srgb, ${c} 13%, transparent)` }}>
      {text.replace(/_/g, " ")}
    </span>
  );
}

/** Inline message for ONE section of a page. Render it right under the button that caused it. */
export function Msg({ err, ok }: { err?: string | null; ok?: string | null }) {
  if (!err && !ok) return null;
  return <div className={`msg ${err ? "err" : "ok"}`} role={err ? "alert" : "status"}>{err || ok}</div>;
}

export function Empty({ children }: { children: React.ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function fmt(d?: string | null) {
  return d ? new Date(d).toLocaleString() : "-";
}

// ---------------------------------------------------------------------------------------------
// Form validation. Every rule names its field, so the message is "<Field name> is required".
// ---------------------------------------------------------------------------------------------
export type Rule = { label: string; value: unknown; email?: boolean; min?: number; required?: boolean };

export function useValidation() {
  const [errors, setErrors] = useState<Record<string, string>>({});

  /** Returns true when every rule passes; otherwise stores a message per failing field. */
  const check = useCallback((rules: Record<string, Rule>) => {
    const next: Record<string, string> = {};
    for (const [key, r] of Object.entries(rules)) {
      const v = r.value;
      const empty = Array.isArray(v) ? v.length === 0 : typeof v === "string" ? v.trim() === "" : v === null || v === undefined;
      if (empty) {
        if (r.required !== false) next[key] = `${r.label} is required`;
        continue;
      }
      if (typeof v === "string") {
        if (r.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v.trim())) next[key] = `${r.label} must be a valid email address`;
        else if (r.min && v.length < r.min) next[key] = `${r.label} must be at least ${r.min} characters`;
      }
    }
    setErrors(next);
    return Object.keys(next).length === 0;
  }, []);

  const clear = useCallback((key: string) => {
    setErrors((p) => { if (!p[key]) return p; const { [key]: _drop, ...rest } = p; return rest; });
  }, []);
  const reset = useCallback(() => setErrors({}), []);
  return { errors, check, clear, reset };
}

/** Redirects to /login when there is no session. Returns the current role once known. */
export function useSession(allowed?: Role[]): { ready: boolean; role: Role | null } {
  const router = useRouter();
  const [state, setState] = useState<{ ready: boolean; role: Role | null }>({ ready: false, role: null });
  useEffect(() => {
    if (!getToken()) { router.replace("/login"); return; }
    setState({ ready: true, role: getRole() });
  }, [router]);
  if (state.ready && allowed && state.role && !allowed.includes(state.role)) {
    return { ready: false, role: state.role };
  }
  return state;
}

export const isStaff = (r: Role | null) => r === "ADMIN" || r === "MANAGER" || r === "TESTER";
export const canDecide = (r: Role | null) => r === "ADMIN" || r === "MANAGER";
