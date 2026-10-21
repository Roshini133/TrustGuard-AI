import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Camera, CheckCheck, Download, FileText, RefreshCw, ShieldCheck } from "lucide-react";
import { api, downloadUrl } from "../lib/api";
import { useAuth } from "../lib/auth";
import { Alert, Badge, Card, DatasetSelect, Empty, ErrorState, Field, fmtDate, Loading, PageHeader, Pager, Spinner, Table } from "../components/ui";

// ---------------- Security & integrity ----------------
export function Security() {
  const { user } = useAuth(); const qc = useQueryClient();
  const q = useQuery({ queryKey: ["integrity"], queryFn: () => api<any>("/api/integrity/overview") });
  const cp = useMutation({ mutationFn: () => api<any>("/api/integrity/audit-checkpoint", { method: "POST", body: {} }), onSuccess: () => qc.invalidateQueries({ queryKey: ["integrity"] }) });
  if (q.isLoading) return <Loading label="Verifying SHA-256 hashes…" />;
  if (q.error) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  const d = q.data; const bad = d.datasets.filter((x: any) => !x.verified).length + d.models.filter((x: any) => !x.verified).length;
  return (
    <>
      <PageHeader title="Security & integrity" subtitle="Live SHA-256 verification of stored datasets and model artifacts, plus audit-chain verification." actions={<button className="btn-secondary" onClick={() => q.refetch()} disabled={q.isFetching}><RefreshCw className={`h-4 w-4 ${q.isFetching ? "animate-spin" : ""}`} /> Re-verify</button>} />
      <div className="mb-4 grid gap-4 md:grid-cols-3">
        <Card><div className="flex items-center gap-3"><ShieldCheck className={bad ? "text-crit" : "text-ok"} /><div><div className="font-semibold">{bad ? `${bad} artifact(s) failed verification` : "All artifacts verified"}</div><div className="text-xs text-muted">{d.datasets.length} dataset versions · {d.models.length} models</div></div></div></Card>
        {d.audit_chain && <Card><div className="flex items-center gap-3"><FileText className={d.audit_chain.valid ? "text-ok" : "text-crit"} /><div><div className="font-semibold">{d.audit_chain.valid ? "Audit chain intact" : `Audit chain broken at event #${d.audit_chain.broken_at}`}</div><div className="text-xs text-muted">{d.audit_chain.checked} events hash-linked</div></div></div></Card>}
        {d.security_event_count != null && <Card><div className="text-2xl font-bold text-primary-dark">{d.security_event_count}</div><div className="text-xs text-muted">Security events recorded</div></Card>}
      </div>
      {user?.role === "admin" && <div className="mb-4 flex items-center gap-3"><button className="btn-secondary" disabled={cp.isPending} onClick={() => cp.mutate()}><Camera className="h-4 w-4" /> Create audit checkpoint</button>{cp.data && <span className="font-mono text-xs text-muted">checkpoint #{cp.data.id} → {cp.data.hash.slice(0, 20)}…</span>}{cp.error && <ErrorState error={cp.error} />}</div>}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Dataset versions">{!d.datasets.length ? <Empty title="No datasets" /> : <Table head={["Dataset", "Ver.", "Kind", "SHA-256", "Status"]}>{d.datasets.map((x: any, i: number) => <tr key={i}><td className="td">{x.dataset}</td><td className="td">v{x.version}</td><td className="td"><Badge value={x.kind} /></td><td className="td font-mono text-xs" title={x.sha256}>{x.sha256.slice(0, 14)}…</td><td className="td"><Badge value={x.verified ? "completed" : "failed"} /></td></tr>)}</Table>}</Card>
        <Card title="Model artifacts">{!d.models.length ? <Empty title="No models" /> : <Table head={["Model", "SHA-256", "Status"]}>{d.models.map((x: any, i: number) => <tr key={i}><td className="td">{x.model}</td><td className="td font-mono text-xs" title={x.sha256}>{x.sha256.slice(0, 14)}…</td><td className="td"><Badge value={x.verified ? "completed" : "failed"} /></td></tr>)}</Table>}</Card>
      </div>
    </>
  );
}

// ---------------- Audit logs ----------------
export function Audit() {
  const [action, setAction] = useState(""); const [sec, setSec] = useState(""); const [page, setPage] = useState(1);
  const q = useQuery({ queryKey: ["audit", action, sec, page], queryFn: () => api<any>(`/api/audit?action=${encodeURIComponent(action)}&page=${page}${sec ? `&security=${sec}` : ""}`), placeholderData: (p) => p });
  return (
    <>
      <PageHeader title="Audit logs" subtitle="Append-only, hash-chained event log. Secrets are never recorded." actions={<><a className="btn-secondary" href={downloadUrl("/api/reports/audit-logs?format=csv")}><Download className="h-4 w-4" /> CSV</a><a className="btn-secondary" href={downloadUrl("/api/reports/audit-logs?format=pdf")}><Download className="h-4 w-4" /> PDF</a></>} />
      <Card>
        <div className="mb-4 flex flex-wrap gap-3"><input className="input w-64" aria-label="Filter by action" placeholder="Filter action, e.g. auth.login" value={action} onChange={(e) => { setAction(e.target.value); setPage(1); }} />
          <select className="input w-44" aria-label="Security filter" value={sec} onChange={(e) => { setSec(e.target.value); setPage(1); }}><option value="">All events</option><option value="true">Security only</option><option value="false">Non-security</option></select></div>
        {q.isLoading ? <Loading /> : q.error ? <ErrorState error={q.error} retry={() => q.refetch()} /> : !q.data.items.length ? <Empty title="No events match" /> : <>
          <Table head={["#", "Time", "Action", "Resource", "Actor", "IP", "Hash"]}>{q.data.items.map((e: any) => <tr key={e.id}><td className="td">{e.id}</td><td className="td whitespace-nowrap">{fmtDate(e.ts)}</td><td className="td font-mono text-xs">{e.action} {e.is_security && <Badge value="warning" />}</td><td className="td text-xs">{e.resource_type} {e.resource_id.slice(0, 8)}</td><td className="td text-xs">{e.actor_id?.slice(0, 8) ?? "—"}</td><td className="td text-xs">{e.ip || "—"}</td><td className="td font-mono text-xs">{e.hash.slice(0, 10)}…</td></tr>)}</Table>
          <Pager page={page} total={q.data.total} pageSize={q.data.page_size} onPage={setPage} /></>}
      </Card>
    </>
  );
}

// ---------------- Reports ----------------
const REPORTS: [string, string, string][] = [
  ["dataset-quality", "Dataset quality", "Missing values, duplicates and issues per pipeline run."], ["trust-scores", "Trust scores", "Record-level trust scores and components (latest run)."],
  ["anomaly-detection", "Anomaly detection", "Per-method anomaly scores with explanations."], ["quarantine", "Quarantine", "Quarantined records and review status."],
  ["provenance", "Provenance", "Dataset versions, sources and SHA-256 hashes."], ["model-training", "Model training", "Registered models and evaluation metrics."],
  ["model-impact", "Model impact", "Clean vs poisoned vs filtered model comparison."], ["experiments", "Poisoning experiments", "Detection precision, recall, FPR, retention."],
  ["audit-logs", "Audit logs", "Latest audit events (administrators only)."],
];

export function Reports() {
  const { user } = useAuth(); const [ds, setDs] = useState("");
  const [all, setAll] = useState(true);
  const qs = (fmt: string) => `?format=${fmt}${!all && ds ? `&dataset_id=${ds}` : ""}`;
  return (
    <>
      <PageHeader title="Reports & exports" subtitle="Download CSV or PDF reports. CSV cells are sanitised against spreadsheet formula injection." />
      <Card className="mb-4"><div className="flex flex-wrap items-end gap-4"><div className="w-72"><DatasetSelect value={ds} onChange={setDs} label="Limit to dataset" /></div>
        <label className="mb-2 flex items-center gap-2 text-sm"><input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} className="rounded border-line text-primary" /> All datasets</label></div></Card>
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
        {REPORTS.filter(([k]) => k !== "audit-logs" || user?.role === "admin").map(([k, t, d]) => <Card key={k}><div className="font-semibold text-primary-navy">{t}</div><p className="mt-1 min-h-[40px] text-sm text-muted">{d}</p>
          <div className="mt-3 flex gap-2"><a className="btn-secondary" href={downloadUrl(`/api/reports/${k}${qs("csv")}`)}><Download className="h-4 w-4" /> CSV</a><a className="btn-primary" href={downloadUrl(`/api/reports/${k}${qs("pdf")}`)}><Download className="h-4 w-4" /> PDF</a></div></Card>)}
      </div>
    </>
  );
}

// ---------------- Notifications ----------------
export function Notifications() {
  const qc = useQueryClient(); const [unread, setUnread] = useState(false);
  const q = useQuery({ queryKey: ["notifications", "list", unread], queryFn: () => api<any>(`/api/notifications?unread_only=${unread}`) });
  const refresh = () => { qc.invalidateQueries({ queryKey: ["notifications"] }); };
  const read = useMutation({ mutationFn: (id: string) => api(`/api/notifications/${id}/read`, { method: "POST", body: {} }), onSuccess: refresh });
  const all = useMutation({ mutationFn: () => api("/api/notifications/read-all", { method: "POST", body: {} }), onSuccess: refresh });
  return (
    <>
      <PageHeader title="Notifications" subtitle="Generated from real pipeline, detection, training, experiment and integrity events." actions={<button className="btn-secondary" onClick={() => all.mutate()} disabled={all.isPending}><CheckCheck className="h-4 w-4" /> Mark all read</button>} />
      <Card right={<label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={unread} onChange={(e) => setUnread(e.target.checked)} className="rounded border-line text-primary" /> Unread only</label>}>
        {q.isLoading ? <Loading /> : q.error ? <ErrorState error={q.error} retry={() => q.refetch()} /> : !q.data.items.length ? <Empty title="You're all caught up" hint="New events will appear here." /> :
          <ul className="divide-y divide-line">{q.data.items.map((n: any) => <li key={n.id} className={`flex items-start justify-between gap-3 py-3 ${n.read ? "opacity-60" : ""}`}><div><div className="flex items-center gap-2 font-medium">{n.title} <Badge value={n.level} /></div><div className="text-sm text-muted">{n.body}</div><div className="text-xs text-muted">{fmtDate(n.created_at)}</div></div>
            {!n.read && <button className="btn-secondary py-1" onClick={() => read.mutate(n.id)}>Mark read</button>}</li>)}</ul>}
      </Card>
    </>
  );
}

// ---------------- User management ----------------
export function Users() {
  const qc = useQueryClient(); const { user: me } = useAuth(); const [search, setSearch] = useState(""); const [err, setErr] = useState("");
  const q = useQuery({ queryKey: ["users", search], queryFn: () => api<any>(`/api/admin/users?search=${encodeURIComponent(search)}`) });
  const roles = useQuery({ queryKey: ["roles"], queryFn: () => api<any>("/api/admin/roles") });
  const patch = useMutation({ mutationFn: (v: { id: string; body: object }) => api(`/api/admin/users/${v.id}`, { method: "PATCH", body: v.body }), onSuccess: () => { setErr(""); qc.invalidateQueries({ queryKey: ["users"] }); }, onError: (e) => setErr((e as Error).message) });
  return (
    <>
      <PageHeader title="User management" subtitle="Assign roles and enable or disable accounts. Disabling revokes active sessions." />
      {err && <div className="mb-3"><Alert kind="error">{err}</Alert></div>}
      <Card><input className="input mb-4 max-w-sm" placeholder="Search users" aria-label="Search users" value={search} onChange={(e) => setSearch(e.target.value)} />
        {q.isLoading ? <Loading /> : q.error ? <ErrorState error={q.error} /> : <Table head={["Name", "Email", "Role", "Active", "Last sign-in", "Joined"]}>{q.data.items.map((u: any) => <tr key={u.id}>
          <td className="td font-medium">{u.full_name}</td><td className="td">{u.email}</td>
          <td className="td"><select className="input w-32 py-1" aria-label={`Role for ${u.email}`} value={u.role} disabled={u.id === me?.id} onChange={(e) => patch.mutate({ id: u.id, body: { role: e.target.value } })}>{(roles.data?.items ?? [{ role: u.role }]).map((r: any) => <option key={r.role}>{r.role}</option>)}</select></td>
          <td className="td"><label className="flex items-center gap-2"><input type="checkbox" checked={u.is_active} disabled={u.id === me?.id} onChange={(e) => patch.mutate({ id: u.id, body: { is_active: e.target.checked } })} className="rounded border-line text-primary" aria-label={`Active ${u.email}`} />{u.is_active ? "Active" : "Disabled"}</label></td>
          <td className="td">{fmtDate(u.last_login_at)}</td><td className="td">{fmtDate(u.created_at)}</td></tr>)}</Table>}</Card>
      <Card title="Role permissions" className="mt-4">{roles.data && <div className="grid gap-3 md:grid-cols-2">{roles.data.items.map((r: any) => <div key={r.role} className="rounded-lg border border-line p-3"><div className="font-semibold capitalize">{r.role}</div><div className="mt-1 flex flex-wrap gap-1">{r.permissions.map((p: string) => <span key={p} className="rounded bg-primary-light px-2 py-0.5 text-xs text-primary-dark">{p === "*" ? "all permissions" : p}</span>)}</div></div>)}</div>}</Card>
    </>
  );
}

// ---------------- System monitoring ----------------
export function System() {
  const h = useQuery({ queryKey: ["health"], queryFn: () => api<any>("/api/admin/health"), refetchInterval: 15_000 });
  const j = useQuery({ queryKey: ["jobs"], queryFn: () => api<any>("/api/admin/jobs"), refetchInterval: 10_000 });
  const e = useQuery({ queryKey: ["errors"], queryFn: () => api<any>("/api/admin/errors") });
  const tone = (ok: boolean | null) => (ok === null ? "bg-slate-100 text-muted" : ok ? "bg-green-50 text-ok" : "bg-red-50 text-crit");
  return (
    <>
      <PageHeader title="System monitoring" subtitle="Dependency health, background jobs and application errors." />
      {h.isLoading ? <Loading /> : h.error ? <ErrorState error={h.error} /> : <div className="mb-4 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {Object.entries(h.data.checks).map(([k, v]: [string, any]) => <Card key={k}><div className="flex items-center justify-between"><div className="font-semibold capitalize">{k}</div><span className={`rounded-full px-2 py-0.5 text-xs font-semibold ${tone(v.ok)}`}>{v.ok === null ? "n/a" : v.ok ? "healthy" : "down"}</span></div><div className="mt-1 text-xs text-muted">{v.note ?? v.backend ?? v.provider ?? v.error ?? ""}</div></Card>)}</div>}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title={`Background jobs${j.data ? ` (mode: ${j.data.mode})` : ""}`}>{j.isLoading ? <Loading /> : !j.data.items.length ? <Empty title="No jobs yet" /> : <>
          <div className="mb-3 flex flex-wrap gap-1">{Object.entries(j.data.counts).map(([k, v]) => <span key={k}><Badge value={`${k}: ${v}`} /></span>)}</div>
          <div className="max-h-96 overflow-y-auto"><Table head={["Kind", "Status", "Created"]}>{j.data.items.map((x: any) => <tr key={x.id}><td className="td capitalize">{x.kind}</td><td className="td"><Badge value={x.status} /></td><td className="td">{fmtDate(x.created_at)}</td></tr>)}</Table></div></>}</Card>
        <Card title="Application errors">{e.isLoading ? <Loading /> : !e.data.items.length ? <Empty title="No failed jobs" hint="Failures in pipelines, detection, training and experiments are listed here." /> : <ul className="divide-y divide-line">{e.data.items.map((x: any) => <li key={x.id} className="py-2 text-sm"><div className="flex justify-between"><Badge value={x.kind} /><span className="text-xs text-muted">{fmtDate(x.created_at)}</span></div><div className="mt-1 text-crit">{x.error}</div></li>)}</ul>}</Card>
      </div>
    </>
  );
}

// ---------------- Settings ----------------
export function Settings() {
  const { user } = useAuth(); const qc = useQueryClient();
  const q = useQuery({ queryKey: ["settings"], queryFn: () => api<any>("/api/admin/settings"), enabled: user?.role === "admin" });
  const [text, setText] = useState(""); const [msg, setMsg] = useState<{ k: "success" | "error"; t: string } | null>(null);
  const save = useMutation({
    mutationFn: () => api("/api/admin/settings", { method: "PUT", body: { detection_defaults: JSON.parse(text || JSON.stringify(q.data?.detection_defaults)) } }),
    onSuccess: () => { setMsg({ k: "success", t: "Settings saved." }); qc.invalidateQueries({ queryKey: ["settings"] }); }, onError: (e) => setMsg({ k: "error", t: e instanceof SyntaxError ? "Invalid JSON." : (e as Error).message }),
  });
  return (
    <>
      <PageHeader title="Settings" subtitle="Your profile and platform configuration." />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Profile"><dl className="space-y-2 text-sm">{[["Name", user?.full_name], ["Email", user?.email], ["Role", user?.role]].map(([k, v]) => <div key={k} className="flex justify-between"><dt className="text-muted">{k}</dt><dd className="font-medium capitalize-first">{v}</dd></div>)}</dl>
          <div className="mt-4"><div className="mb-1 text-sm font-semibold">Permissions</div><div className="flex flex-wrap gap-1">{user?.permissions.map((p) => <span key={p} className="rounded bg-primary-light px-2 py-0.5 text-xs text-primary-dark">{p === "*" ? "all" : p}</span>)}</div></div></Card>
        {user?.role === "admin" && <Card title="Detection defaults (JSON)">{q.isLoading ? <Loading /> : <>
          <textarea className="input h-64 font-mono text-xs" aria-label="Detection defaults JSON" defaultValue={JSON.stringify(q.data?.detection_defaults, null, 2)} onChange={(e) => setText(e.target.value)} />
          {msg && <div className="mt-2"><Alert kind={msg.k}>{msg.t}</Alert></div>}
          <button className="btn-primary mt-3" onClick={() => { setMsg(null); save.mutate(); }} disabled={save.isPending}>{save.isPending && <Spinner className="h-4 w-4" />} Save settings</button></>}</Card>}
      </div>
    </>
  );
}

// ---------------- Help ----------------
export function Help() {
  const S = ({ id, t, children }: { id?: string; t: string; children: React.ReactNode }) => <Card title={t} className="scroll-mt-20"><div id={id} className="space-y-2 text-sm text-ink">{children}</div></Card>;
  return (
    <>
      <PageHeader title="Help & documentation" subtitle="How TrustGuard AI works and how to read its results." />
      <div className="grid gap-4 lg:grid-cols-2">
        <S t="Quick start"><ol className="list-decimal space-y-1 pl-5"><li>Upload a CSV/XLSX (or generate a sample) and name the label column.</li><li>Run the <b>Data engineering</b> pipeline to validate and clean.</li><li>Run <b>AI trust analysis</b> to score every record.</li><li>Review quarantined records, then create a filtered version.</li><li>Train models, or run a <b>poisoning experiment</b> to measure impact.</li></ol></S>
        <S t="Data Trust Score"><p>Trust = 100 × (0.25·statistical normality + 0.25·label consistency + 0.20·provenance + 0.15·data quality + 0.15·model-impact safety). Weights and thresholds are configurable.</p><p>80–100 high trust · 50–79 requires review · below 50 highly suspicious. <b>Invalid</b> data and <b>insufficient evidence</b> are separate classes, and an integrity failure is never masked by a high score.</p></S>
        <S t="Interpreting detections"><p>Anomalies are statistical evidence, not proof of malicious intent. Backdoor-style poisoning, in particular, can be hard to detect with outlier methods; treat results as triage, not a verdict.</p></S>
        <S t="Roles"><ul className="list-disc pl-5"><li><b>Viewer</b> — read-only.</li><li><b>Analyst</b> — upload, process, analyse, train, experiment on own datasets.</li><li><b>Reviewer</b> — review and release quarantined records.</li><li><b>Admin</b> — everything, plus users, audit and system.</li></ul></S>
        <S id="terms" t="Terms of use"><p>This academic platform is provided as-is for research and education. Do not upload data you are not authorised to process.</p></S>
        <S id="privacy" t="Privacy"><p>Your name, email and hashed password are stored to operate your account. Passwords, one-time codes and reset tokens are never stored in plaintext. Uploaded data stays in this deployment's storage.</p></S>
      </div>
    </>
  );
}
