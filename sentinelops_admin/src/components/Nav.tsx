"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { getRole, getToken, Role, setSession } from "@/lib/api";

function Shield() {
  return (
    <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 3l8 3v6c0 4.5-3.2 8.2-8 9-4.8-.8-8-4.5-8-9V6l8-3z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  );
}

export default function Nav() {
  const router = useRouter();
  const path = usePathname();
  const [role, setRole] = useState<Role | null>(null);
  const [authed, setAuthed] = useState(false);
  const [theme, setTheme] = useState<"dark" | "light">("dark");

  useEffect(() => {
    setAuthed(!!getToken());
    setRole(getRole());
  }, [path]);

  useEffect(() => {
    const t = document.documentElement.getAttribute("data-theme");
    setTheme(t === "light" ? "light" : "dark");
  }, []);

  function toggleTheme() {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("so-theme", next); } catch { /* private mode: keep the choice for this tab only */ }
  }

  const link = (href: string, label: string) => (
    <Link key={href} href={href} className={`navlink${path === href ? " active" : ""}`}>{label}</Link>
  );

  return (
    <nav className="topbar">
      <Link href={authed ? "/" : "/login"} className="brand">
        <span className="brand-mark"><Shield /></span>SentinelOps
      </Link>
      {authed && link("/dashboard", "Dashboard")}
      {authed && link("/", "Engagements")}
      {authed && role !== "CLIENT" && link("/clients", "Clients")}
      {authed && role === "ADMIN" && link("/users", "Users")}
      {authed && (role === "ADMIN" || role === "MANAGER") && link("/audit", "Audit log")}
      {authed && (role === "ADMIN" || role === "MANAGER") && link("/settings", "Settings")}
      {link("/status", "Status")}
      <div className="nav-right">
        <button className="icon-btn" onClick={toggleTheme} aria-label="Switch between dark and light theme" title="Switch theme">
          {theme === "dark" ? "☀" : "☾"}
        </button>
        {authed ? (
          <>
            <span className="role-chip">{role}</span>
            <a href="#" onClick={(e) => { e.preventDefault(); setSession(null); setAuthed(false); router.push("/login"); }}>Sign out</a>
          </>
        ) : link("/login", "Sign in")}
      </div>
    </nav>
  );
}
