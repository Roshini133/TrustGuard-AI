import { useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Activity, Bell, BookOpen, Boxes, ClipboardList, Database, FileBarChart, FlaskConical, GitBranch, Gauge, LayoutDashboard,
  ListChecks, LogOut, Menu, Settings, ShieldAlert, ShieldCheck, Upload, Users, Workflow, X, AlertOctagon, BrainCircuit, FileText,
} from "lucide-react";
import { useAuth } from "../lib/auth";
import { api } from "../lib/api";

const NAV: { to: string; label: string; icon: any; perm?: string; admin?: boolean }[] = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/datasets", label: "Datasets", icon: Database },
  { to: "/datasets/upload", label: "Upload dataset", icon: Upload, perm: "dataset:write" },
  { to: "/pipeline", label: "Data engineering", icon: Workflow },
  { to: "/trust-analysis", label: "AI trust analysis", icon: BrainCircuit },
  { to: "/suspicious", label: "Suspicious records", icon: ShieldAlert },
  { to: "/quarantine", label: "Quarantine center", icon: AlertOctagon },
  { to: "/training", label: "Model training", icon: Gauge },
  { to: "/models", label: "Model registry", icon: Boxes },
  { to: "/model-impact", label: "Model impact", icon: Activity },
  { to: "/experiments", label: "Experiment lab", icon: FlaskConical },
  { to: "/lineage", label: "Dataset lineage", icon: GitBranch },
  { to: "/quality", label: "Data-quality reports", icon: ListChecks },
  { to: "/security", label: "Security & integrity", icon: ShieldCheck },
  { to: "/audit", label: "Audit logs", icon: ClipboardList, admin: true },
  { to: "/reports", label: "Reports & exports", icon: FileBarChart },
  { to: "/notifications", label: "Notifications", icon: Bell },
  { to: "/users", label: "User management", icon: Users, admin: true },
  { to: "/system", label: "System monitoring", icon: Activity, admin: true },
  { to: "/settings", label: "Settings", icon: Settings },
  { to: "/help", label: "Help & docs", icon: BookOpen },
];

export default function Layout() {
  const { user, logout, can } = useAuth();
  const nav = useNavigate();
  const [open, setOpen] = useState(false);
  const notes = useQuery({ queryKey: ["notifications"], queryFn: () => api<{ unread: number }>("/api/notifications"), refetchInterval: 30_000 });
  const items = NAV.filter((n) => (!n.perm || can(n.perm)) && (!n.admin || user?.role === "admin"));
  const sidebar = (
    <nav className="flex h-full flex-col">
      <div className="flex items-center gap-2 px-5 py-5 text-lg font-bold text-white"><ShieldCheck className="h-6 w-6" /> TrustGuard AI</div>
      <div className="flex-1 space-y-0.5 overflow-y-auto px-3 pb-4">
        {items.map(({ to, label, icon: Icon }) => (
          <NavLink key={to} to={to} end={to === "/" || to === "/datasets"} onClick={() => setOpen(false)}
            className={({ isActive }) => `flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition ${isActive ? "bg-white text-primary-dark" : "text-blue-100 hover:bg-white/10"}`}>
            <Icon className="h-4 w-4" /> {label}
          </NavLink>
        ))}
      </div>
    </nav>
  );
  return (
    <div className="min-h-screen lg:pl-64">
      <aside className="fixed inset-y-0 left-0 hidden w-64 bg-primary-dark lg:block">{sidebar}</aside>
      {open && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-primary-navy/50" onClick={() => setOpen(false)} />
          <aside className="absolute inset-y-0 left-0 w-64 bg-primary-dark">{sidebar}</aside>
        </div>
      )}
      <header className="sticky top-0 z-30 flex items-center justify-between border-b border-line bg-white/95 px-4 py-3 backdrop-blur">
        <button className="rounded p-2 hover:bg-primary-light lg:hidden" aria-label={open ? "Close menu" : "Open menu"} onClick={() => setOpen(!open)}>{open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}</button>
        <div className="hidden text-sm text-muted lg:block">Cloud-native data-poisoning detection & secure ML</div>
        <div className="flex items-center gap-3">
          <button className="relative rounded-lg p-2 hover:bg-primary-light" aria-label="Notifications" onClick={() => nav("/notifications")}>
            <Bell className="h-5 w-5 text-primary-dark" />
            {!!notes.data?.unread && <span className="absolute -right-0.5 -top-0.5 min-w-[18px] rounded-full bg-crit px-1 text-center text-[10px] font-bold text-white">{notes.data.unread > 99 ? "99+" : notes.data.unread}</span>}
          </button>
          <div className="hidden text-right sm:block"><div className="text-sm font-semibold leading-tight">{user?.full_name}</div><div className="text-xs capitalize text-muted">{user?.role}</div></div>
          <button className="btn-secondary" onClick={async () => { await logout(); nav("/login"); }}><LogOut className="h-4 w-4" /><span className="hidden sm:inline">Sign out</span></button>
        </div>
      </header>
      <main className="mx-auto max-w-7xl p-4 sm:p-6 fade-in"><Outlet /></main>
    </div>
  );
}
