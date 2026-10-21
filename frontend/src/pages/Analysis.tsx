import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Download, Play, ShieldCheck } from "lucide-react";
import { api, ApiError, downloadUrl } from "../lib/api";
import { useAuth } from "../lib/auth";
import { Alert, Badge, Card, DatasetSelect, Empty, ErrorState, Field, fmtDate, Loading, Modal, num, PageHeader, Pager, pct, Spinner, Table } from "../components/ui";

const active = (s: string) => s === "queued" || s === "running";

// ---------------- Data engineering pipeline ----------------
export function Pipeline() {
  const { can } = useAuth(); const qc = useQueryClient(); const [ds, setDs] = useState("");
  const runs = useQuery({ queryKey: ["pipeline-runs", ds], enabled: !!ds, queryFn: () => api<any>(`/api/datasets/${ds}/pipeline-runs`), refetchInterval: (q) => (q.state.data?.items?.some((r: any) => active(r.status)) ? 2000 : false) });
  const start = useMutation({ mutationFn: () => api(`/api/datasets/${ds}/pipeline`, { method: "POST", body: {} }), onSuccess: () => { qc.invalidateQueries({ queryKey: ["pipeline-runs", ds] }); qc.invalidateQueries({ queryKey: ["datasets"] }); } });
  const latest = runs.data?.items?.[0];
  return (
    <>
      <PageHeader title="Data engineering pipeline" subtitle="Schema validation, missing/duplicate/invalid analysis, cleaning and versioning. The raw artifact is never modified." />
      <Card className="mb-4"><div className="flex flex-wrap items-end gap-3"><div className="min-w-[240px] flex-1"><DatasetSelect value={ds} onChange={setDs} /></div>
        {can("pipeline:run") && <button className="btn-primary mb-0.5" disabled={!ds || start.isPending || active(latest?.status ?? "")} onClick={() => start.mutate()}>{start.isPending ? <Spinner className="h-4 w-4" /> : <Play className="h-4 w-4" />} Run pipeline</button>}</div>
        {start.error && <div className="mt-3"><ErrorState error={start.error} /></div>}</Card>
      {runs.isLoading ? <Loading /> : !runs.data?.items?.length ? <Card><Empty title="No pipeline runs yet" hint="Run the pipeline to validate and clean this dataset." /></Card> : <>
        <Card title="Run history"><Table head={["Started", "Status", "Rows before", "Rows after", "Issue types", "Error"]}>
          {runs.data.items.map((r: any) => <tr key={r.id}><td className="td">{fmtDate(r.created_at)}</td><td className="td"><Badge value={r.status} /></td><td className="td">{r.report?.rows_before ?? "—"}</td><td className="td">{r.report?.rows_after ?? "—"}</td><td className="td">{r.report?.quality?.issue_count ?? "—"}</td><td className="td text-crit">{r.error}</td></tr>)}</Table></Card>
        {latest?.status === "completed" && <QualityReport report={latest.report} />}</>}
    </>
  );
}

function QualityReport({ report }: { report: any }) {
  const q = report.quality;
  const miss = Object.entries(q.missing_by_column).map(([k, v]) => ({ column: k, missing: v as number }));
  return (
    <div className="mt-4 grid gap-4 lg:grid-cols-2">
      <Card title="Data-quality summary"><dl className="grid grid-cols-2 gap-3 text-sm">
        {[["Rows", q.rows], ["Columns", q.columns], ["Missing cells", `${q.missing_cells} (${q.missing_pct}%)`], ["Duplicate rows", q.duplicate_rows], ["Constant columns", q.constant_columns.length || "none"], ["Invalid-value columns", Object.keys(q.invalid_values).length || "none"]]
          .map(([k, v]) => <div key={String(k)} className="rounded-lg bg-primary-light p-3"><dt className="text-xs text-muted">{k}</dt><dd className="font-semibold">{v}</dd></div>)}</dl>
        {q.label && <div className="mt-3 text-sm"><div className="mb-1 font-medium">Class balance (imbalance ratio {q.label.imbalance_ratio.toFixed(2)})</div>{Object.entries(q.label.classes).map(([k, v]) => <span key={k} className="mr-2"><Badge value={`${k}: ${v}`} /></span>)}</div>}</Card>
      <Card title="Missing values by column">{!miss.length ? <Empty title="No missing values" /> : <div className="h-56"><ResponsiveContainer><BarChart data={miss}><CartesianGrid strokeDasharray="3 3" stroke="#DBEAFE" /><XAxis dataKey="column" fontSize={11} /><YAxis allowDecimals={false} fontSize={11} /><Tooltip /><Bar dataKey="missing" fill="#2563EB" radius={[4, 4, 0, 0]} /></BarChart></ResponsiveContainer></div>}</Card>
      <Card title="Transformations applied" className="lg:col-span-2">{!report.transformations.length ? <Empty title="No transformations were needed" /> :
        <Table head={["Step", "Column", "Count", "Detail"]}>{report.transformations.map((t: any, i: number) => <tr key={i}><td className="td font-mono text-xs">{t.step}</td><td className="td">{t.column ?? "—"}</td><td className="td">{t.count ?? t.values_invalidated ?? "—"}</td><td className="td">{t.value !== undefined ? String(t.value) : ""}</td></tr>)}</Table>}</Card>
    </div>
  );
}

// ---------------- Data-quality report page ----------------
export function Quality() {
  const [ds, setDs] = useState("");
  const runs = useQuery({ queryKey: ["pipeline-runs", ds], enabled: !!ds, queryFn: () => api<any>(`/api/datasets/${ds}/pipeline-runs`) });
  const latest = runs.data?.items?.find((r: any) => r.status === "completed");
  return (
    <>
      <PageHeader title="Data-quality reports" subtitle="Results of the most recent completed pipeline run." actions={<>
        <a className="btn-secondary" href={downloadUrl(`/api/reports/dataset-quality?format=csv&dataset_id=${ds}`)}><Download className="h-4 w-4" /> CSV</a>
        <a className="btn-secondary" href={downloadUrl(`/api/reports/dataset-quality?format=pdf&dataset_id=${ds}`)}><Download className="h-4 w-4" /> PDF</a></>} />
      <Card className="mb-4 max-w-md"><DatasetSelect value={ds} onChange={setDs} /></Card>
      {runs.isLoading ? <Loading /> : !latest ? <Card><Empty title="No quality report yet" hint="Run the data-engineering pipeline for this dataset first." action={<Link className="btn-primary" to="/pipeline">Go to pipeline</Link>} /></Card> : <QualityReport report={latest.report} />}
    </>
  );
}

// ---------------- AI trust analysis ----------------
const CATS = ["", "high_trust", "requires_review", "highly_suspicious", "invalid", "insufficient_evidence"];

function Components({ r }: { r: any }) {
  const items: [string, number | null][] = [["Statistical normality", r.statistical_normality], ["Label consistency", r.label_consistency], ["Provenance", r.provenance], ["Data quality", r.data_quality], ["Model-impact safety", r.model_impact]];
  return <div className="space-y-1.5">{items.map(([k, v]) => <div key={k} className="text-xs"><div className="flex justify-between"><span>{k}</span><span className="font-mono">{v == null ? "no evidence" : v.toFixed(2)}</span></div><div className="h-1.5 rounded bg-primary-light"><div className="h-1.5 rounded bg-primary" style={{ width: `${(v ?? 0) * 100}%` }} /></div></div>)}</div>;
}

function ResultsTable({ runId, fixedCats }: { runId: string; fixedCats?: string[] }) {
  const [cat, setCat] = useState(fixedCats?.[0] ?? ""); const [page, setPage] = useState(1); const [sel, setSel] = useState<any>(null);
  const q = useQuery({ queryKey: ["results", runId, cat, page], queryFn: () => api<any>(`/api/detection-runs/${runId}/results?category=${cat}&page=${page}&page_size=15`), placeholderData: (p) => p });
  return (
    <Card title="Record-level results" right={<select aria-label="Category" className="input w-52" value={cat} onChange={(e) => { setCat(e.target.value); setPage(1); }}>{(fixedCats ?? CATS).map((c) => <option key={c} value={c}>{c ? c.replace(/_/g, " ") : "All categories"}</option>)}</select>}>
      {q.isLoading ? <Loading /> : q.error ? <ErrorState error={q.error} /> : !q.data.items.length ? <Empty title="No records in this category" /> : <>
        <Table head={["Row", "Trust", "Category", "IForest", "LOF", "Dist.", "Label cons.", "Why flagged"]}>
          {q.data.items.map((r: any) => <tr key={r.row_index} className="cursor-pointer hover:bg-primary-light/50" onClick={() => setSel(r)}>
            <td className="td font-mono">{r.row_index}</td><td className="td font-semibold">{r.trust_score == null ? "—" : r.trust_score.toFixed(1)}</td><td className="td"><Badge value={r.category} /></td>
            <td className="td">{num(r.iforest_score, 2)}</td><td className="td">{num(r.lof_score, 2)}</td><td className="td">{num(r.distribution_score, 2)}</td><td className="td">{num(r.label_consistency, 2)}</td>
            <td className="td max-w-xs truncate text-muted" title={(r.explanation ?? []).join(" ")}>{r.explanation?.[0] ?? "—"}</td></tr>)}</Table>
        <Pager page={page} total={q.data.total} pageSize={q.data.page_size} onPage={setPage} /></>}
      {sel && <Modal title={`Row ${sel.row_index} — trust ${sel.trust_score == null ? "n/a" : sel.trust_score.toFixed(1)}`} onClose={() => setSel(null)}>
        <div className="grid gap-4 sm:grid-cols-2"><div><div className="mb-2 text-sm font-semibold">Evidence components</div><Components r={sel} /></div>
          <div><div className="mb-2 text-sm font-semibold">Explanation</div>{sel.explanation?.length ? <ul className="list-disc space-y-1 pl-4 text-sm">{sel.explanation.map((e: string, i: number) => <li key={i}>{e}</li>)}</ul> : <p className="text-sm text-muted">No concerning signals.</p>}</div></div>
        <p className="mt-4 text-xs text-muted">An anomaly is statistical evidence, not proof of malicious behaviour.</p></Modal>}
    </Card>
  );
}

function useLatestRun(ds: string) {
  const runs = useQuery({ queryKey: ["detection-runs", ds], enabled: !!ds, queryFn: () => api<any>(`/api/datasets/${ds}/detection-runs`), refetchInterval: (q) => (q.state.data?.items?.some((r: any) => active(r.status)) ? 2000 : false) });
  return { runs, latest: runs.data?.items?.find((r: any) => r.status === "completed") };
}

export function TrustAnalysis() {
  const { can } = useAuth(); const qc = useQueryClient(); const [ds, setDs] = useState("");
  const [cfg, setCfg] = useState({ high: 80, review: 50, contamination: 0.05, w: { statistical_normality: 0.25, label_consistency: 0.25, provenance: 0.2, data_quality: 0.15, model_impact: 0.15 } });
  const { runs, latest } = useLatestRun(ds);
  const hist = useQuery({ queryKey: ["hist", ds, latest?.id], enabled: !!latest, queryFn: () => api<any>(`/api/datasets/${ds}/trust-histogram`) });
  const start = useMutation({
    mutationFn: () => api(`/api/datasets/${ds}/detect`, { body: { high_trust_min: cfg.high, review_min: cfg.review, contamination: cfg.contamination, weights: cfg.w } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["detection-runs", ds] }),
  });
  const running = runs.data?.items?.some((r: any) => active(r.status));
  const s = latest?.summary;
  return (
    <>
      <PageHeader title="AI trust analysis" subtitle="Isolation Forest, Local Outlier Factor, distribution and label-consistency analysis combined into a Data Trust Score." />
      <Card title="Run configuration" className="mb-4">
        <div className="grid gap-3 md:grid-cols-4"><div className="md:col-span-2"><DatasetSelect value={ds} onChange={setDs} /></div>
          <Field label="High-trust threshold"><input type="number" className="input" min={0} max={100} value={cfg.high} onChange={(e) => setCfg({ ...cfg, high: +e.target.value })} /></Field>
          <Field label="Review threshold"><input type="number" className="input" min={0} max={100} value={cfg.review} onChange={(e) => setCfg({ ...cfg, review: +e.target.value })} /></Field></div>
        <details className="mt-3 text-sm"><summary className="cursor-pointer font-medium text-primary">Advanced: weights & contamination</summary>
          <div className="mt-3 grid gap-3 sm:grid-cols-3 lg:grid-cols-6">{Object.entries(cfg.w).map(([k, v]) => <Field key={k} label={k.replace(/_/g, " ")}><input className="input" type="number" step="0.05" min={0} value={v} onChange={(e) => setCfg({ ...cfg, w: { ...cfg.w, [k]: +e.target.value } })} /></Field>)}
            <Field label="contamination"><input className="input" type="number" step="0.01" min={0.01} max={0.5} value={cfg.contamination} onChange={(e) => setCfg({ ...cfg, contamination: +e.target.value })} /></Field></div>
          <p className="mt-2 text-xs text-muted">Weights are normalised to sum to 1. Trust = 100 × Σ weight × component (0–1).</p></details>
        {can("detect:run") && <button className="btn-primary mt-4" disabled={!ds || start.isPending || running} onClick={() => start.mutate()}>{start.isPending || running ? <Spinner className="h-4 w-4" /> : <Play className="h-4 w-4" />} {running ? "Analysing…" : "Run analysis"}</button>}
        {start.error && <div className="mt-3"><ErrorState error={start.error} /></div>}</Card>
      {runs.isLoading ? <Loading /> : !latest ? <Card><Empty title="No analysis yet" hint={runs.data?.items?.[0]?.status === "failed" ? runs.data.items[0].error : "Run an analysis to compute record-level trust scores."} /></Card> : <>
        <div className="grid gap-4 lg:grid-cols-3">
          <Card title="Dataset trust"><div className="text-4xl font-bold text-primary-dark">{s.dataset_trust_score == null ? "—" : s.dataset_trust_score.toFixed(1)}<span className="text-lg text-muted"> / 100</span></div>
            <div className="mt-3 flex flex-wrap gap-1">{Object.entries(s.category_counts).map(([k, v]) => <span key={k}><Badge value={`${k}: ${v}`} /></span>)}</div>
            {!s.integrity_verified && <div className="mt-3"><Alert kind="error">SHA-256 integrity verification failed — critical.</Alert></div>}
            {!!s.evidence_missing?.length && <div className="mt-3"><Alert kind="warning">Missing evidence (neutral value used): {s.evidence_missing.join(", ")}</Alert></div>}
            <p className="mt-3 text-xs text-muted">Run took {latest.duration_s.toFixed(1)}s · {fmtDate(latest.created_at)}</p></Card>
          <Card title="Detection-method flags"><Table head={["Method", "Flagged"]}>{Object.entries(s.method_flags).map(([k, v]) => <tr key={k}><td className="td capitalize">{k.replace(/_/g, " ")}</td><td className="td font-semibold">{v == null ? "n/a (no label)" : String(v)}</td></tr>)}</Table></Card>
          <Card title="Trust-score distribution"><div className="h-44"><ResponsiveContainer><BarChart data={hist.data?.bins ?? []}><XAxis dataKey="range" fontSize={9} /><YAxis allowDecimals={false} fontSize={10} /><Tooltip /><Bar dataKey="count" fill="#2563EB" radius={[3, 3, 0, 0]} /></BarChart></ResponsiveContainer></div></Card>
        </div>
        <div className="mt-4"><Alert kind="info">{s.disclaimer}</Alert></div>
        <div className="mt-4"><ResultsTable runId={latest.id} /></div></>}
    </>
  );
}

export function Suspicious() {
  const [ds, setDs] = useState(""); const { latest, runs } = useLatestRun(ds);
  return (
    <>
      <PageHeader title="Suspicious records" subtitle="Records the latest analysis rated as requiring review, highly suspicious, or invalid." actions={<Link className="btn-primary" to="/quarantine">Quarantine center</Link>} />
      <Card className="mb-4 max-w-md"><DatasetSelect value={ds} onChange={setDs} /></Card>
      {runs.isLoading ? <Loading /> : !latest ? <Card><Empty title="No analysis available" hint="Run AI trust analysis first." action={<Link className="btn-primary" to="/trust-analysis">Run analysis</Link>} /></Card> :
        <ResultsTable key={latest.id} runId={latest.id} fixedCats={["highly_suspicious", "requires_review", "invalid"]} />}
    </>
  );
}

// ---------------- Quarantine ----------------
const QSTAT = ["", "quarantined", "investigating", "approved", "rejected", "released"];

export function Quarantine() {
  const { can } = useAuth(); const qc = useQueryClient();
  const [status, setStatus] = useState("quarantined"); const [page, setPage] = useState(1); const [sel, setSel] = useState<string | null>(null);
  const q = useQuery({ queryKey: ["quarantine", status, page], queryFn: () => api<any>(`/api/quarantine?status=${status}&page=${page}`), placeholderData: (p) => p });
  const filter = useMutation({ mutationFn: (ds: string) => api<any>(`/api/datasets/${ds}/apply-filter`, { method: "POST", body: {} }), onSuccess: () => qc.invalidateQueries() });
  const ds0 = q.data?.items?.[0]?.dataset_id;
  return (
    <>
      <PageHeader title="Quarantine center" subtitle="Review suspicious records. Release requires prior approval and a reviewer or administrator role." actions={
        can("pipeline:run") && ds0 && <button className="btn-secondary" disabled={filter.isPending} onClick={() => filter.mutate(ds0)}><ShieldCheck className="h-4 w-4" /> Create filtered version</button>} />
      {filter.data && <div className="mb-3"><Alert kind="success">Filtered version created: {filter.data.rows_removed} records excluded, {filter.data.rows_kept} kept. The raw and cleaned versions are unchanged.</Alert></div>}
      {filter.error && <div className="mb-3"><ErrorState error={filter.error} /></div>}
      <Card right={<select aria-label="Status" className="input w-44" value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }}>{QSTAT.map((s) => <option key={s} value={s}>{s || "All"}</option>)}</select>}>
        {q.isLoading ? <Loading /> : q.error ? <ErrorState error={q.error} retry={() => q.refetch()} /> : !q.data.items.length ? <Empty title="Nothing in this queue" hint="Records rated highly suspicious or invalid are quarantined automatically after analysis." /> : <>
          <Table head={["Dataset", "Row", "Trust", "Status", "Primary reason", ""]}>{q.data.items.map((r: any) => <tr key={r.id}>
            <td className="td">{r.dataset_name}</td><td className="td font-mono">{r.row_index}</td><td className="td font-semibold">{r.trust_score == null ? "—" : r.trust_score.toFixed(1)}</td><td className="td"><Badge value={r.status} /></td>
            <td className="td max-w-sm truncate text-muted" title={r.reasons?.join(" ")}>{r.reasons?.[0]}</td><td className="td"><button className="btn-secondary py-1" onClick={() => setSel(r.id)}>Review</button></td></tr>)}</Table>
          <Pager page={page} total={q.data.total} pageSize={q.data.page_size} onPage={setPage} /></>}
      </Card>
      {sel && <ReviewModal id={sel} onClose={() => setSel(null)} />}
    </>
  );
}

function ReviewModal({ id, onClose }: { id: string; onClose: () => void }) {
  const { can } = useAuth(); const qc = useQueryClient(); const [notes, setNotes] = useState(""); const [err, setErr] = useState("");
  const q = useQuery({ queryKey: ["qrec", id], queryFn: () => api<any>(`/api/quarantine/${id}`) });
  const dec = useMutation({
    mutationFn: (decision: string) => api(`/api/quarantine/${id}/decision`, { body: { decision, notes } }),
    onSuccess: () => { setNotes(""); setErr(""); qc.invalidateQueries({ queryKey: ["qrec", id] }); qc.invalidateQueries({ queryKey: ["quarantine"] }); },
    onError: (e) => setErr(e instanceof ApiError ? e.message : "Failed"),
  });
  return (
    <Modal title="Review quarantined record" onClose={onClose}>
      {q.isLoading ? <Loading /> : q.error ? <ErrorState error={q.error} /> : <div className="space-y-4">
        <div className="flex items-center gap-2 text-sm"><Badge value={q.data.status} /> <span>Trust {q.data.trust_score == null ? "n/a" : q.data.trust_score.toFixed(1)}</span> <span className="text-muted">· {q.data.dataset_name} · row {q.data.row_index}</span></div>
        <div className="grid gap-4 sm:grid-cols-2"><div><div className="mb-1 text-sm font-semibold">Detection reasons</div><ul className="list-disc space-y-1 pl-4 text-sm">{q.data.reasons.map((r: string, i: number) => <li key={i}>{r}</li>)}</ul></div>
          {q.data.components && <div><div className="mb-1 text-sm font-semibold">Evidence</div><Components r={q.data.components} /></div>}</div>
        <div><div className="mb-1 text-sm font-semibold">Record values</div><div className="max-h-40 overflow-auto rounded-lg border border-line"><table className="w-full text-xs"><tbody>{Object.entries(q.data.row).map(([k, v]) => <tr key={k}><td className="td font-medium">{k}</td><td className="td font-mono">{v == null ? "null" : String(v)}</td></tr>)}</tbody></table></div></div>
        <div><div className="mb-1 text-sm font-semibold">Decision history</div>{!q.data.decisions.length ? <p className="text-sm text-muted">No decisions yet.</p> : <ul className="space-y-1 text-sm">{q.data.decisions.map((d: any) => <li key={d.id}><Badge value={d.decision} /> <span className="text-muted">{fmtDate(d.created_at)}</span> {d.notes && <span>— {d.notes}</span>}</li>)}</ul>}</div>
        {can("quarantine:review") && <div className="space-y-2 border-t border-line pt-4"><Field label="Review notes (required for reject and release)"><textarea className="input" rows={2} value={notes} onChange={(e) => setNotes(e.target.value)} /></Field>
          {err && <Alert kind="error">{err}</Alert>}
          <div className="flex flex-wrap gap-2"><button className="btn-primary" disabled={dec.isPending} onClick={() => dec.mutate("approve")}>Approve</button><button className="btn-danger" disabled={dec.isPending} onClick={() => dec.mutate("reject")}>Reject</button>
            <button className="btn-secondary" disabled={dec.isPending} onClick={() => dec.mutate("investigate")}>Needs investigation</button>
            {can("quarantine:release") && <button className="btn-secondary" disabled={dec.isPending || q.data.status !== "approved"} title={q.data.status !== "approved" ? "Approve first" : ""} onClick={() => dec.mutate("release")}>Release</button>}</div></div>}
      </div>}
    </Modal>
  );
}

// ---------------- Model training / registry ----------------
export function Training() {
  const { can } = useAuth(); const qc = useQueryClient(); const [ds, setDs] = useState(""); const [type, setType] = useState("random_forest");
  const dsq = useQuery({ queryKey: ["dataset", ds], enabled: !!ds, queryFn: () => api<any>(`/api/datasets/${ds}`) });
  const [ver, setVer] = useState(""); const [target, setTarget] = useState("");
  const runs = useQuery({ queryKey: ["training-runs"], queryFn: () => api<any>("/api/training-runs"), refetchInterval: (q) => (q.state.data?.items?.some((r: any) => active(r.status)) ? 2000 : false) });
  const start = useMutation({ mutationFn: () => api(`/api/datasets/${ds}/train`, { body: { model_type: type, version_id: ver || null, target: target || null } }), onSuccess: () => { qc.invalidateQueries({ queryKey: ["training-runs"] }); qc.invalidateQueries({ queryKey: ["models"] }); } });
  return (
    <>
      <PageHeader title="Model training" subtitle="Reproducible training (fixed seed, 80/20 stratified split) with preprocessing and evaluation." />
      {can("model:train") && <Card title="Train a model" className="mb-4"><div className="grid gap-3 md:grid-cols-4">
        <DatasetSelect value={ds} onChange={(v) => { setDs(v); setVer(""); }} />
        <Field label="Dataset version"><select className="input" value={ver} onChange={(e) => setVer(e.target.value)}><option value="">Latest raw/cleaned</option>{dsq.data?.versions.map((v: any) => <option key={v.id} value={v.id}>v{v.version} ({v.kind}, {v.n_rows} rows)</option>)}</select></Field>
        <Field label="Algorithm"><select className="input" value={type} onChange={(e) => setType(e.target.value)}><option value="logistic_regression">Logistic Regression</option><option value="random_forest">Random Forest</option><option value="decision_tree">Decision Tree</option></select></Field>
        <Field label="Target column" hint={dsq.data?.label_column ? `Default: ${dsq.data.label_column}` : "Required"}><input className="input" value={target} onChange={(e) => setTarget(e.target.value)} placeholder={dsq.data?.label_column ?? "label"} /></Field></div>
        <button className="btn-primary mt-4" disabled={!ds || start.isPending} onClick={() => start.mutate()}>{start.isPending ? <Spinner className="h-4 w-4" /> : <Play className="h-4 w-4" />} Train model</button>
        {start.error && <div className="mt-3"><ErrorState error={start.error} /></div>}</Card>}
      <Card title="Training runs">{runs.isLoading ? <Loading /> : !runs.data.items.length ? <Empty title="No training runs yet" /> : <Table head={["Started", "Dataset", "Algorithm", "Status", "Accuracy", "F1", "ROC-AUC", "Train time", "Error"]}>
        {runs.data.items.map((r: any) => <tr key={r.id}><td className="td">{fmtDate(r.created_at)}</td><td className="td">{r.dataset_name}</td><td className="td">{r.model_type.replace(/_/g, " ")}</td><td className="td"><Badge value={r.status} /></td><td className="td">{num(r.metrics?.accuracy)}</td><td className="td">{num(r.metrics?.f1)}</td><td className="td">{num(r.metrics?.roc_auc)}</td><td className="td">{r.status === "completed" ? `${r.train_time_s.toFixed(2)}s` : "—"}</td><td className="td text-crit">{r.error}</td></tr>)}</Table>}</Card>
    </>
  );
}

export function Models() {
  const q = useQuery({ queryKey: ["models"], queryFn: () => api<any>("/api/models") });
  const [res, setRes] = useState<Record<string, boolean>>({});
  const verify = useMutation({ mutationFn: (id: string) => api<any>(`/api/models/${id}/verify`, { method: "POST", body: {} }), onSuccess: (r) => setRes((p) => ({ ...p, [r.model_id]: r.verified })) });
  return (
    <>
      <PageHeader title="Model registry" subtitle="Versioned models with dataset associations and SHA-256 artifact hashes." actions={<a className="btn-secondary" href={downloadUrl("/api/reports/model-training?format=csv")}><Download className="h-4 w-4" /> Export CSV</a>} />
      <Card>{q.isLoading ? <Loading /> : q.error ? <ErrorState error={q.error} retry={() => q.refetch()} /> : !q.data.items.length ? <Empty title="No registered models" hint="Train a model to register it here." action={<Link className="btn-primary" to="/training">Train a model</Link>} /> :
        <Table head={["Model", "Version", "Algorithm", "Accuracy", "F1", "SHA-256", "Created", "Integrity"]}>{q.data.items.map((m: any) => <tr key={m.id}><td className="td font-medium">{m.name}</td><td className="td">v{m.version}</td><td className="td">{m.model_type.replace(/_/g, " ")}</td><td className="td">{num(m.metrics.accuracy)}</td><td className="td">{num(m.metrics.f1)}</td><td className="td font-mono text-xs" title={m.sha256}>{m.sha256.slice(0, 14)}…</td><td className="td">{fmtDate(m.created_at)}</td>
          <td className="td">{m.id in res ? <Badge value={res[m.id] ? "completed" : "failed"} /> : <button className="btn-secondary py-1" onClick={() => verify.mutate(m.id)}>Verify</button>}</td></tr>)}</Table>}</Card>
    </>
  );
}

// ---------------- Experiments & model impact ----------------
export function Experiments() {
  const { can } = useAuth(); const qc = useQueryClient(); const [ds, setDs] = useState("");
  const [f, setF] = useState({ name: "", attack: "label_flip", poison_rate: 0.1, model_type: "random_forest" });
  const q = useQuery({ queryKey: ["experiments"], queryFn: () => api<any>("/api/experiments"), refetchInterval: (x) => (x.state.data?.items?.some((e: any) => active(e.status)) ? 2000 : false) });
  const start = useMutation({ mutationFn: () => api("/api/experiments", { body: { ...f, name: f.name || `${f.attack}-${Math.round(f.poison_rate * 100)}%`, dataset_id: ds } }), onSuccess: () => qc.invalidateQueries({ queryKey: ["experiments"] }) });
  const [sel, setSel] = useState<any>(null);
  return (
    <>
      <PageHeader title="Experiment laboratory" subtitle="Controlled poisoning on copies of your data. Detection never sees ground-truth labels; evaluation uses an untouched clean test set." />
      {can("experiment:run") && <Card title="New experiment" className="mb-4"><div className="grid gap-3 md:grid-cols-5"><DatasetSelect value={ds} onChange={setDs} />
        <Field label="Attack"><select className="input" value={f.attack} onChange={(e) => setF({ ...f, attack: e.target.value })}><option value="label_flip">Label flipping</option><option value="feature_manipulation">Feature manipulation</option><option value="injection">Data injection</option><option value="backdoor">Backdoor-style</option></select></Field>
        <Field label={`Poison rate: ${Math.round(f.poison_rate * 100)}%`}><input type="range" min={0.02} max={0.4} step={0.01} value={f.poison_rate} onChange={(e) => setF({ ...f, poison_rate: +e.target.value })} className="w-full accent-primary" /></Field>
        <Field label="Model"><select className="input" value={f.model_type} onChange={(e) => setF({ ...f, model_type: e.target.value })}><option value="logistic_regression">Logistic Regression</option><option value="random_forest">Random Forest</option><option value="decision_tree">Decision Tree</option></select></Field>
        <Field label="Name (optional)"><input className="input" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field></div>
        <button className="btn-primary mt-4" disabled={!ds || start.isPending} onClick={() => start.mutate()}>{start.isPending ? <Spinner className="h-4 w-4" /> : <Play className="h-4 w-4" />} Run experiment</button>
        {start.error && <div className="mt-3"><ErrorState error={start.error} /></div>}</Card>}
      <Card title="Experiments">{q.isLoading ? <Loading /> : !q.data.items.length ? <Empty title="No experiments yet" hint="Run a poisoning experiment to measure detection and model impact." /> :
        <Table head={["Name", "Dataset", "Attack", "Rate", "Status", "Precision", "Recall", "FPR", "F1", ""]}>{q.data.items.map((e: any) => { const d = e.results?.detection; return <tr key={e.id}>
          <td className="td font-medium">{e.name}</td><td className="td">{e.dataset_name}</td><td className="td">{e.attack.replace(/_/g, " ")}</td><td className="td">{Math.round(e.poison_rate * 100)}%</td><td className="td"><Badge value={e.status} /></td>
          <td className="td">{num(d?.precision, 2)}</td><td className="td">{num(d?.recall, 2)}</td><td className="td">{num(d?.false_positive_rate, 2)}</td><td className="td">{num(d?.f1, 2)}</td>
          <td className="td">{e.status === "completed" ? <button className="btn-secondary py-1" onClick={() => setSel(e)}>Details</button> : e.error && <span className="text-xs text-crit">{e.error}</span>}</td></tr>; })}</Table>}</Card>
      {sel && <Modal title={sel.name} onClose={() => setSel(null)}><ExperimentDetail e={sel} /></Modal>}
    </>
  );
}

function ExperimentDetail({ e }: { e: any }) {
  const r = e.results; const d = r.detection;
  return (
    <div className="space-y-4 text-sm">
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">{[["Train rows", r.n_train], ["Poisoned", r.n_poisoned], ["Flagged", r.n_flagged], ["Clean test rows", r.n_test]].map(([k, v]) => <div key={String(k)} className="rounded-lg bg-primary-light p-3"><div className="text-xs text-muted">{k}</div><div className="font-semibold">{v}</div></div>)}</div>
      <Table head={["Detection metric", "Value"]}>{[["Precision", num(d.precision)], ["Recall", num(d.recall)], ["False-positive rate", num(d.false_positive_rate)], ["Accuracy", num(d.accuracy)], ["F1", num(d.f1)], ["ROC-AUC", num(d.roc_auc)], ["Training-data retention", pct(d.retention)], ["Detection time", `${d.detection_time_s.toFixed(2)}s`], ["Flag threshold (trust <)", d.flag_below]].map(([k, v]) => <tr key={String(k)}><td className="td">{k}</td><td className="td font-semibold">{v}</td></tr>)}</Table>
      <Table head={["Model", "Accuracy", "Precision", "Recall", "F1", "ROC-AUC", "Train time"]}>{(["clean", "poisoned", "filtered"] as const).map((k) => r[k] ? <tr key={k}><td className="td capitalize font-medium">{k}</td><td className="td">{num(r[k].accuracy)}</td><td className="td">{num(r[k].precision)}</td><td className="td">{num(r[k].recall)}</td><td className="td">{num(r[k].f1)}</td><td className="td">{num(r[k].roc_auc)}</td><td className="td">{r[k].train_time_s.toFixed(2)}s</td></tr> : <tr key={k}><td className="td capitalize">{k}</td><td className="td text-muted" colSpan={6}>Not available (too few records/classes after filtering)</td></tr>)}</Table>
      <p className="text-xs text-muted">{r.note}</p>
    </div>
  );
}

export function ModelImpact() {
  const q = useQuery({ queryKey: ["experiments"], queryFn: () => api<any>("/api/experiments") });
  const done = (q.data?.items ?? []).filter((e: any) => e.status === "completed");
  const [id, setId] = useState("");
  const e = done.find((x: any) => x.id === id) ?? done[0];
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  const chart = e ? ["accuracy", "precision", "recall", "f1"].map((m) => ({ metric: m, clean: e.results.clean[m], poisoned: e.results.poisoned[m], filtered: e.results.filtered?.[m] ?? null })) : [];
  return (
    <>
      <PageHeader title="Model-impact analysis" subtitle="Clean baseline vs poisoned-data model vs filtered-data model, all scored on the same untouched clean test set." actions={<a className="btn-secondary" href={downloadUrl("/api/reports/model-impact?format=pdf")}><Download className="h-4 w-4" /> PDF</a>} />
      {!e ? <Card><Empty title="No completed experiments" hint="Run an experiment to compare models." action={<Link className="btn-primary" to="/experiments">Open experiment lab</Link>} /></Card> : <>
        <Card className="mb-4 max-w-md"><Field label="Experiment"><select className="input" value={e.id} onChange={(x) => setId(x.target.value)}>{done.map((x: any) => <option key={x.id} value={x.id}>{x.name} — {x.dataset_name}</option>)}</select></Field></Card>
        <Card title="Test-set performance"><div className="h-72"><ResponsiveContainer><BarChart data={chart}><CartesianGrid strokeDasharray="3 3" stroke="#DBEAFE" /><XAxis dataKey="metric" /><YAxis domain={[0, 1]} /><Tooltip formatter={(v: number) => (v == null ? "n/a" : v.toFixed(3))} /><Legend /><Bar dataKey="clean" fill="#1E3A8A" /><Bar dataKey="poisoned" fill="#DC2626" /><Bar dataKey="filtered" fill="#2563EB" /></BarChart></ResponsiveContainer></div></Card>
        <div className="mt-4"><Card title="Details"><ExperimentDetail e={e} /></Card></div></>}
    </>
  );
}

// ---------------- Lineage ----------------
export function Lineage() {
  const [ds, setDs] = useState("");
  const q = useQuery({ queryKey: ["lineage", ds], enabled: !!ds, queryFn: () => api<any>(`/api/datasets/${ds}/lineage`) });
  const label = (id: string) => q.data?.nodes.find((n: any) => n.id === id)?.label ?? id.slice(0, 8);
  const ICON: Record<string, string> = { version: "bg-primary text-white", model: "bg-ok text-white", experiment: "bg-warn text-white" };
  return (
    <>
      <PageHeader title="Dataset lineage" subtitle="How versions, models and experiments derive from the original upload." />
      <Card className="mb-4 max-w-md"><DatasetSelect value={ds} onChange={setDs} /></Card>
      {q.isLoading ? <Loading /> : q.error ? <ErrorState error={q.error} /> : !q.data ? null : <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Artifacts"><ul className="space-y-2">{q.data.nodes.map((n: any) => <li key={n.id} className="flex items-start gap-3 rounded-lg border border-line p-3 text-sm"><span className={`rounded px-2 py-0.5 text-xs font-semibold ${ICON[n.type]}`}>{n.type}</span><div><div className="font-medium">{n.label}</div>{n.sha256 && <div className="font-mono text-xs text-muted">{n.sha256.slice(0, 24)}…</div>}{n.transformation && <div className="text-xs text-muted">{n.transformation}</div>}</div></li>)}</ul>
          <div className="mt-4 rounded-lg bg-primary-light p-3 text-sm"><div className="font-semibold">Source metadata</div>Declared source: {q.data.source.declared_source || "not declared"}</div></Card>
        <Card title="Derivation graph">{!q.data.edges.length ? <Empty title="No derivations yet" hint="Processing, training and filtering add edges here." /> : <ul className="space-y-2">{q.data.edges.map((e: any, i: number) => <li key={i} className="flex flex-wrap items-center gap-2 text-sm"><span className="rounded bg-primary-light px-2 py-1 font-medium">{label(e.from)}</span><span className="text-primary">— {e.operation} →</span><span className="rounded bg-primary-light px-2 py-1 font-medium">{label(e.to)}</span></li>)}</ul>}</Card></div>}
    </>
  );
}
