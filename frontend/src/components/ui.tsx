import { ReactNode, useEffect } from "react";
import { AlertTriangle, CheckCircle2, Inbox, Loader2, X } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";

export const Spinner = ({ className = "h-5 w-5" }: { className?: string }) => <Loader2 className={`animate-spin text-primary ${className}`} aria-label="Loading" />;

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h1 className="text-2xl font-bold text-primary-navy">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}

export const Card = ({ title, children, className = "", right }: { title?: string; children: ReactNode; className?: string; right?: ReactNode }) => (
  <section className={`card p-5 ${className}`}>
    {(title || right) && <div className="mb-4 flex items-center justify-between gap-2">{title && <h2 className="text-base font-semibold text-primary-navy">{title}</h2>}{right}</div>}
    {children}
  </section>
);

export const Loading = ({ label = "Loading…" }: { label?: string }) => (
  <div role="status" className="flex items-center justify-center gap-2 p-10 text-sm text-muted"><Spinner /> {label}</div>
);

export const ErrorState = ({ error, retry }: { error: unknown; retry?: () => void }) => (
  <div role="alert" className="flex items-start gap-3 rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-crit">
    <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
    <div className="flex-1">{error instanceof Error ? error.message : "Something went wrong."}</div>
    {retry && <button className="font-semibold underline" onClick={retry}>Retry</button>}
  </div>
);

export const Empty = ({ title, hint, action }: { title: string; hint?: string; action?: ReactNode }) => (
  <div className="flex flex-col items-center gap-2 p-10 text-center">
    <div className="rounded-full bg-primary-light p-3 text-primary"><Inbox className="h-6 w-6" /></div>
    <p className="font-semibold text-primary-navy">{title}</p>
    {hint && <p className="max-w-md text-sm text-muted">{hint}</p>}
    {action}
  </div>
);

export const Alert = ({ kind = "info", children }: { kind?: "info" | "success" | "error" | "warning"; children: ReactNode }) => {
  const m = { info: "border-line bg-primary-light text-primary-dark", success: "border-green-200 bg-green-50 text-ok", error: "border-red-200 bg-red-50 text-crit", warning: "border-amber-200 bg-amber-50 text-warn" }[kind];
  const Icon = kind === "success" ? CheckCircle2 : AlertTriangle;
  return <div role={kind === "error" ? "alert" : "status"} className={`flex items-start gap-2 rounded-lg border p-3 text-sm ${m}`}><Icon className="mt-0.5 h-4 w-4 shrink-0" /><div>{children}</div></div>;
};

const BADGE: Record<string, string> = {
  high_trust: "bg-green-50 text-ok border-green-200", completed: "bg-green-50 text-ok border-green-200", processed: "bg-green-50 text-ok border-green-200", approved: "bg-green-50 text-ok border-green-200", released: "bg-green-50 text-ok border-green-200",
  requires_review: "bg-amber-50 text-warn border-amber-200", awaiting_review: "bg-amber-50 text-warn border-amber-200", investigating: "bg-amber-50 text-warn border-amber-200", warning: "bg-amber-50 text-warn border-amber-200",
  highly_suspicious: "bg-red-50 text-crit border-red-200", failed: "bg-red-50 text-crit border-red-200", rejected: "bg-red-50 text-crit border-red-200", invalid: "bg-red-50 text-crit border-red-200", critical: "bg-red-50 text-crit border-red-200", quarantined: "bg-red-50 text-crit border-red-200",
};
export const Badge = ({ value }: { value: string }) => (
  <span className={`inline-block whitespace-nowrap rounded-full border px-2 py-0.5 text-xs font-semibold ${BADGE[value] ?? "bg-primary-light text-primary-dark border-line"}`}>{value.replace(/_/g, " ")}</span>
);

export const Field = ({ label, error, hint, children }: { label: string; error?: string; hint?: string; children: ReactNode }) => (
  <label className="block text-sm">
    <span className="mb-1 block font-medium text-ink">{label}</span>
    {children}
    {hint && !error && <span className="mt-1 block text-xs text-muted">{hint}</span>}
    {error && <span role="alert" className="mt-1 block text-xs text-crit">{error}</span>}
  </label>
);

export function Table({ head, children }: { head: string[]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-line">
      <table className="min-w-full"><thead><tr>{head.map((h) => <th key={h} className="th">{h}</th>)}</tr></thead><tbody>{children}</tbody></table>
    </div>
  );
}

export function Pager({ page, total, pageSize, onPage }: { page: number; total: number; pageSize: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <div className="mt-3 flex items-center justify-between text-sm text-muted">
      <span>{total} total</span>
      <div className="flex items-center gap-2">
        <button className="btn-secondary" disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous</button>
        <span>Page {page} / {pages}</span>
        <button className="btn-secondary" disabled={page >= pages} onClick={() => onPage(page + 1)}>Next</button>
      </div>
    </div>
  );
}

export function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  useEffect(() => { const h = (e: KeyboardEvent) => e.key === "Escape" && onClose(); window.addEventListener("keydown", h); return () => window.removeEventListener("keydown", h); }, [onClose]);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-primary-navy/40 p-4" role="dialog" aria-modal="true" aria-label={title}>
      <div className="card max-h-[90vh] w-full max-w-2xl overflow-y-auto p-6 fade-in">
        <div className="mb-4 flex items-center justify-between"><h2 className="text-lg font-semibold text-primary-navy">{title}</h2><button aria-label="Close" onClick={onClose} className="rounded p-1 hover:bg-primary-light"><X className="h-5 w-5" /></button></div>
        {children}
      </div>
    </div>
  );
}

export const Stat = ({ label, value, icon, tone = "primary" }: { label: string; value: ReactNode; icon: ReactNode; tone?: "primary" | "warn" | "crit" | "ok" }) => {
  const t = { primary: "bg-primary-light text-primary", warn: "bg-amber-50 text-warn", crit: "bg-red-50 text-crit", ok: "bg-green-50 text-ok" }[tone];
  return (
    <div className="card flex items-center gap-4 p-4">
      <div className={`rounded-lg p-3 ${t}`}>{icon}</div>
      <div><div className="text-2xl font-bold text-primary-navy">{value}</div><div className="text-xs font-medium text-muted">{label}</div></div>
    </div>
  );
};

export const fmtDate = (s?: string | null) => (s ? new Date(s.endsWith("Z") || /[+-]\d\d:?\d\d$/.test(s) ? s : s + "Z").toLocaleString() : "—");
export const pct = (v?: number | null, d = 1) => (v == null ? "—" : `${(v * 100).toFixed(d)}%`);
export const num = (v?: number | null, d = 3) => (v == null ? "—" : v.toFixed(d));

export function DatasetSelect({ value, onChange, label = "Dataset" }: { value: string; onChange: (id: string) => void; label?: string }) {
  const q = useQuery({ queryKey: ["datasets", "all"], queryFn: () => api<{ items: any[] }>("/api/datasets?page_size=100") });
  useEffect(() => { if (!value && q.data?.items.length) onChange(q.data.items[0].id); }, [q.data, value, onChange]);
  return (
    <Field label={label}>
      <select className="input" value={value} onChange={(e) => onChange(e.target.value)} disabled={q.isLoading}>
        {!q.data?.items.length && <option value="">No datasets available</option>}
        {q.data?.items.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
      </select>
    </Field>
  );
}
