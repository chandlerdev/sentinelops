"use client";

import { colors } from "@/components/ui";

export const SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"];
export const SEV_COLOR: Record<string, string> = {
  CRITICAL: colors.bad, HIGH: colors.orange, MEDIUM: colors.warn, LOW: colors.accent, INFORMATIONAL: colors.muted,
};

export function Stat({ label, value, color }: { label: string; value: number | string; color?: string }) {
  return (
    <div style={{ background: colors.bg, border: `1px solid ${colors.border}`, borderRadius: 10, padding: "12px 14px" }}>
      <div style={{ fontSize: 26, fontWeight: 700, color: color || colors.text }}>{value}</div>
      <div style={{ fontSize: 12, color: colors.muted }}>{label}</div>
    </div>
  );
}

export function SeverityBars({ counts }: { counts: Record<string, number> }) {
  const max = Math.max(1, ...SEV.map((s) => counts[s] || 0));
  return (
    <div>
      {SEV.map((s) => (
        <div key={s} style={{ display: "flex", alignItems: "center", gap: 10, margin: "6px 0", fontSize: 13 }}>
          <span style={{ width: 110, color: colors.muted }}>{s.charAt(0) + s.slice(1).toLowerCase()}</span>
          <div style={{ flex: 1, background: colors.bg, borderRadius: 6, height: 14, overflow: "hidden" }}>
            <div style={{ width: `${((counts[s] || 0) / max) * 100}%`, height: "100%", background: SEV_COLOR[s] }} />
          </div>
          <span style={{ width: 28, textAlign: "right" }}>{counts[s] || 0}</span>
        </div>
      ))}
    </div>
  );
}
