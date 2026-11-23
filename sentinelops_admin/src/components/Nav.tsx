"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { getRole, getToken, Role, setSession } from "@/lib/api";
import { colors } from "@/components/ui";

export default function Nav() {
  const router = useRouter();
  const path = usePathname();
  const [role, setRole] = useState<Role | null>(null);
  const [authed, setAuthed] = useState(false);

  useEffect(() => {
    setAuthed(!!getToken());
    setRole(getRole());
  }, [path]);

  const link = (href: string, label: string) => (
    <Link key={href} href={href} style={{
      color: path === href ? colors.text : colors.muted, textDecoration: "none", fontSize: 13, marginRight: 18,
    }}>{label}</Link>
  );

  return (
    <nav style={{
      display: "flex", alignItems: "center", padding: "12px 20px", borderBottom: `1px solid ${colors.border}`,
      background: colors.panel, flexWrap: "wrap", gap: 4,
    }}>
      <strong style={{ marginRight: 24, letterSpacing: "-0.01em" }}>SentinelOps</strong>
      {authed && link("/dashboard", "Dashboard")}
      {authed && link("/", "Engagements")}
      {authed && role !== "CLIENT" && link("/clients", "Clients")}
      {authed && role === "ADMIN" && link("/users", "Users")}
      {authed && (role === "ADMIN" || role === "MANAGER") && link("/audit", "Audit log")}
      {authed && (role === "ADMIN" || role === "MANAGER") && link("/settings", "Settings")}
      {link("/status", "Status")}
      <span style={{ marginLeft: "auto", fontSize: 12, color: colors.muted }}>
        {authed ? (
          <>
            {role}{" "}
            <a href="#" onClick={(e) => { e.preventDefault(); setSession(null); setAuthed(false); router.push("/login"); }}
               style={{ color: colors.accent, marginLeft: 8 }}>Sign out</a>
          </>
        ) : link("/login", "Sign in")}
      </span>
    </nav>
  );
}
