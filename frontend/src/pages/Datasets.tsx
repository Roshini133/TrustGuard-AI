import { FormEvent, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, FileUp, Search, ShieldCheck, Sparkles } from "lucide-react";
import { api, ApiError, downloadUrl } from "../lib/api";
import { useAuth } from "../lib/auth";
import { Alert, Badge, Card, Empty, ErrorState, Field, fmtDate, Loading, PageHeader, Pager, Spinner, Table } from "../components/ui";

export function Datasets() {
  const { can } = useAuth(); const qc = useQueryClient();
  const [search, setSearch] = useState(""); const [status, setStatus] = useState(""); const [page, setPage] = useState(1);
  const q = useQuery({ queryKey: ["datasets", search, status, page], queryFn: () => api<any>(`/api/datasets?page=${page}&search=${encodeURIComponent(search)}&status=${status}`), placeholderData: (p) => p });
  const sample = useMutation({ mutationFn: () => api("/api/datasets/sample", { body: { rows: 600, features: 8, name: `sample-${Date.now().toString(36)}` } }), onSuccess: () => qc.invalidateQueries({ queryKey: ["datasets"] }) });
  return (
    <>
      <PageHeader title="Datasets" subtitle="Uploaded datasets, versions and processing status." actions={can("dataset:write") && <>
        <button className="btn-secondary" onClick={() => sample.mutate()} disabled={sample.isPending}>{sample.isPending ? <Spinner className="h-4 w-4" /> : <Sparkles className="h-4 w-4" />} Generate sample</button>
        <Link to="/datasets/upload" className="btn-primary"><FileUp className="h-4 w-4" /> Upload dataset</Link></>} />
      {sample.error && <div className="mb-3"><ErrorState error={sample.error} /></div>}
      <Card>
        <div className="mb-4 flex flex-wrap gap-3">
          <div className="relative min-w-[220px] flex-1"><Search className="absolute left-3 top-2.5 h-4 w-4 text-muted" /><input className="input pl-9" placeholder="Search by name, source or description" aria-label="Search datasets" value={search} onChange={(e) => { setSearch(e.target.value); setPage(1); }} /></div>
          <select className="input w-48" aria-label="Filter by status" value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }}>
            <option value="">All statuses</option>{["uploaded", "processing", "processed", "awaiting_review", "failed"].map((s) => <option key={s} value={s}>{s.replace("_", " ")}</option>)}</select>
        </div>
        {q.isLoading ? <Loading /> : q.error ? <ErrorState error={q.error} retry={() => q.refetch()} /> : !q.data.items.length ?
          <Empty title="No datasets found" hint="Upload a CSV or XLSX file, or generate a sample dataset to try the platform." /> : <>
            <Table head={["Name", "Source", "Rows", "Cols", "Versions", "Status", "Created", "SHA-256"]}>
              {q.data.items.map((d: any) => <tr key={d.id} className="hover:bg-primary-light/50">
                <td className="td font-medium"><Link className="text-primary hover:underline" to={`/datasets/${d.id}`}>{d.name}</Link></td><td className="td">{d.source || "—"}</td>
                <td className="td">{d.n_rows.toLocaleString()}</td><td className="td">{d.n_cols}</td><td className="td">{d.n_versions}</td><td className="td"><Badge value={d.status} /></td>
                <td className="td whitespace-nowrap">{fmtDate(d.created_at)}</td><td className="td font-mono text-xs" title={d.sha256}>{d.sha256?.slice(0, 12)}…</td></tr>)}
            </Table>
            <Pager page={page} total={q.data.total} pageSize={q.data.page_size} onPage={setPage} /></>}
      </Card>
    </>
  );
}

export function DatasetUpload() {
  const nav = useNavigate(); const qc = useQueryClient();
  const [file, setFile] = useState<File | null>(null);
  const [f, setF] = useState({ name: "", source: "", label_column: "", description: "" });
  const [err, setErr] = useState("");
  const m = useMutation({
    mutationFn: () => { const fd = new FormData(); fd.append("file", file!); Object.entries(f).forEach(([k, v]) => fd.append(k, v)); return api<any>("/api/datasets", { form: fd }); },
    onSuccess: (d) => { qc.invalidateQueries({ queryKey: ["datasets"] }); nav(`/datasets/${d.id}`); },
    onError: (e) => setErr(e instanceof ApiError ? e.message : "Upload failed."),
  });
  const submit = (e: FormEvent) => {
    e.preventDefault(); setErr("");
    if (!file) return setErr("Choose a CSV or XLSX file.");
    if (!/\.(csv|xlsx)$/i.test(file.name)) return setErr("Only .csv and .xlsx files are supported.");
    if (file.size > 50 * 1024 * 1024) return setErr("File exceeds the 50 MB limit.");
    m.mutate();
  };
  return (
    <>
      <PageHeader title="Upload dataset" subtitle="The original file is stored unchanged with a SHA-256 hash. Processing always creates new versions." />
      <Card className="max-w-2xl">
        <form onSubmit={submit} className="space-y-4">
          {err && <Alert kind="error">{err}</Alert>}
          <Field label="File (.csv or .xlsx, max 50 MB)"><input type="file" accept=".csv,.xlsx" className="input" onChange={(e) => {
            const picked = e.target.files?.[0] ?? null;
            setFile(picked);
            if (picked) setF((p) => ({ ...p, name: p.name || picked.name.replace(/\.[^.]+$/, "") }));
          }} /></Field>
          <Field label="Dataset name"><input className="input" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
          <Field label="Source / provenance" hint="Where did this data come from? A declared source raises provenance reliability."><input className="input" value={f.source} onChange={(e) => setF({ ...f, source: e.target.value })} placeholder="e.g. UCI repository, internal CRM export" /></Field>
          <Field label="Label (target) column" hint="Required for label-consistency analysis, model training and experiments."><input className="input" value={f.label_column} onChange={(e) => setF({ ...f, label_column: e.target.value })} placeholder="e.g. label" /></Field>
          <Field label="Description"><textarea className="input" rows={3} value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></Field>
          <button className="btn-primary" disabled={m.isPending}>{m.isPending ? <Spinner className="h-4 w-4" /> : <FileUp className="h-4 w-4" />} Upload</button>
        </form>
      </Card>
    </>
  );
}

export function DatasetDetail() {
  const { id } = useParams(); const { can } = useAuth();
  const [ver, setVer] = useState("");
  const q = useQuery({ queryKey: ["dataset", id], queryFn: () => api<any>(`/api/datasets/${id}`) });
  const pv = useQuery({ queryKey: ["preview", id, ver], queryFn: () => api<any>(`/api/datasets/${id}/preview?version_id=${ver}&rows=15`), enabled: !!q.data });
  const verify = useMutation({ mutationFn: () => api<any>(`/api/datasets/${id}/verify-integrity`, { method: "POST", body: {} }) });
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  const d = q.data;
  return (
    <>
      <PageHeader title={d.name} subtitle={d.description || "No description"} actions={<>
        <button className="btn-secondary" onClick={() => verify.mutate()} disabled={verify.isPending}><ShieldCheck className="h-4 w-4" /> Verify integrity</button>
        {can("dataset:write") && <a className="btn-secondary" href={downloadUrl(`/api/datasets/${id}/download?version_id=${ver}`)}><Download className="h-4 w-4" /> Download</a>}
        <Link className="btn-primary" to="/pipeline">Process</Link></>} />
      {verify.data && <div className="mb-4"><Alert kind={verify.data.all_verified ? "success" : "error"}>{verify.data.all_verified ? "All versions match their recorded SHA-256 hashes." : "Integrity failure: at least one version does not match its recorded hash."}</Alert></div>}
      {verify.error && <ErrorState error={verify.error} />}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card title="Metadata"><dl className="space-y-2 text-sm">
          {[["Status", <Badge value={d.status} />], ["Source", d.source || "—"], ["Label column", d.label_column || "—"], ["Rows × columns", `${d.n_rows} × ${d.n_cols}`], ["Created", fmtDate(d.created_at)]].map(([k, v], i) => <div key={i} className="flex justify-between gap-3"><dt className="text-muted">{k}</dt><dd className="text-right font-medium">{v}</dd></div>)}</dl></Card>
        <Card title="Versions" className="lg:col-span-2">
          <Table head={["#", "Kind", "Rows", "Transformation", "SHA-256", "Verified"]}>
            {d.versions.map((v: any) => { const r = verify.data?.versions?.find((x: any) => x.version_id === v.id);
              return <tr key={v.id} className={ver === v.id ? "bg-primary-light" : ""}><td className="td"><button className="font-semibold text-primary" onClick={() => setVer(v.id)}>v{v.version}</button></td><td className="td"><Badge value={v.kind} /></td><td className="td">{v.n_rows}</td><td className="td">{v.transformation}</td><td className="td font-mono text-xs" title={v.sha256}>{v.sha256.slice(0, 16)}…</td><td className="td">{r ? <Badge value={r.verified ? "completed" : "failed"} /> : "—"}</td></tr>; })}
          </Table></Card>
      </div>
      <Card title="Preview" className="mt-4">
        {pv.isLoading ? <Loading /> : pv.error ? <ErrorState error={pv.error} /> : <>
          {!pv.data.integrity_ok && <div className="mb-3"><Alert kind="error">This version failed integrity verification.</Alert></div>}
          <div className="overflow-x-auto rounded-lg border border-line"><table className="min-w-full"><thead><tr>{pv.data.columns.map((c: string) => <th key={c} className="th">{c}</th>)}</tr></thead>
            <tbody>{pv.data.rows.map((r: any[], i: number) => <tr key={i}>{r.map((v, j) => <td key={j} className="td">{v == null ? <span className="text-muted">null</span> : String(v)}</td>)}</tr>)}</tbody></table></div>
          <p className="mt-2 text-xs text-muted">Showing first {pv.data.rows.length} of {pv.data.total_rows} rows.</p></>}
      </Card>
    </>
  );
}
