"use client";

import React, { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { getRole, getToken, Role } from "@/lib/api";

// Shared look (dark theme, inline styles). Kept in one place so pages stay small.
export const colors = {
  bg: "#0f1115", panel: "#171a21", border: "#2a2f3a", text: "#e6e9ef", muted: "#9aa3b2",
  accent: "#5b8cff", ok: "#3fb950", warn: "#d29922", bad: "#f85149", orange: "#ff7b45",
};

export const fieldStyle: React.CSSProperties = {
  padding: "9px 11px", borderRadius: 8, background: colors.bg, border: `1px solid ${colors.border}`,
  color: colors.text, fontSize: 14, width: "100%", boxSizing: "border-box",
};

export function Card({ title, children, right }: { title?: string; children: React.ReactNode; right?: React.ReactNode }) {
  return (
    <section style={{ background: colors.panel, border: `1px solid ${colors.border}`, borderRadius: 12, padding: 18, marginTop: 18 }}>
      {(title || right) && (
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
          <h2 style={{ fontSize: 15, margin: 0 }}>{title}</h2>
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
  const bg = kind === "primary" ? colors.accent : kind === "danger" ? colors.bad : "transparent";
  return (
    <button type={type} onClick={onClick} disabled={disabled} style={{
      padding: small ? "5px 10px" : "9px 14px", borderRadius: 8, fontSize: small ? 12 : 13, fontWeight: 600,
      cursor: disabled ? "default" : "pointer", opacity: disabled ? 0.6 : 1, color: kind === "ghost" ? colors.text : "#fff",
      background: bg, border: kind === "ghost" ? `1px solid ${colors.border}` : "none", marginRight: 6,
    }}>{children}</button>
  );
}

export function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label style={{ display: "block", fontSize: 12, color: colors.muted }}>
      {label}
      <div style={{ marginTop: 4 }}>{children}</div>
    </label>
  );
}

export function Grid({ children, min = 220 }: { children: React.ReactNode; min?: number }) {
  return <div style={{ display: "grid", gridTemplateColumns: `repeat(auto-fit, minmax(${min}px, 1fr))`, gap: 12 }}>{children}</div>;
}

const badgeColor: Record<string, string> = {
  VERIFIED: colors.ok, SIGNED: colors.ok, LAB: colors.accent, COMPLETED: colors.ok, PASSED: colors.ok,
  UNVERIFIED: colors.muted, DRAFT: colors.muted, EXPIRED: colors.warn, PENDING: colors.warn,
  CRITICAL: colors.bad, HIGH: colors.orange, MEDIUM: colors.warn, LOW: colors.accent, INFORMATIONAL: colors.muted,
  OPEN: colors.warn, IN_PROGRESS: colors.accent, FIXED: colors.accent, RETEST_PASS: colors.ok, RETEST_FAIL: colors.bad,
  CLOSED: colors.ok, FALSE_POSITIVE: colors.muted, QUEUED: colors.muted, RUNNING: colors.accent, STOPPED: colors.muted,
  PENDING_APPROVAL: colors.warn, REJECTED: colors.bad, REVOKED: colors.bad, FAILED: colors.bad,
};
export function Badge({ text }: { text: string }) {
  const c = badgeColor[text] || colors.muted;
  return (
    <span style={{ padding: "2px 9px", borderRadius: 999, fontSize: 11, fontWeight: 600, color: c, border: `1px solid ${c}` }}>
      {text.replace("_", " ")}
    </span>
  );
}

export function Msg({ err, ok }: { err?: string | null; ok?: string | null }) {
  if (!err && !ok) return null;
  return <p style={{ color: err ? colors.bad : colors.ok, fontSize: 13, margin: "10px 0 0" }}>{err || ok}</p>;
}

export function fmt(d?: string | null) {
  return d ? new Date(d).toLocaleString() : "-";
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
