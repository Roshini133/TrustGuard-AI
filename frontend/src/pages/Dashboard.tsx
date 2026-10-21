import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, Cell, Legend, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Activity, AlertOctagon, Boxes, Database, FileWarning, FlaskConical, ListChecks, ShieldAlert, Table2 } from "lucide-react";
import { api } from "../lib/api";
import { Badge, Card, Empty, ErrorState, fmtDate, Loading, PageHeader, Stat } from "../components/ui";

const BLUES = ["#2563EB", "#60A5FA", "#1E3A8A", "#93C5FD"];
const PIE = ["#16A34A", "#D97706", "#DC2626", "#94A3B8"];

function ChartBox({ title, empty, children }: { title: string; empty: boolean; children: React.ReactNode }) {
  return (
    <Card title={title}>
      {empty ? <Empty title="No data yet" hint="This chart fills in after you analyse datasets or run experiments." /> : <div className="h-64">{children}</div>}
    </Card>
  );
}

export default function Dashboard() {
  const q = useQuery({ queryKey: ["dashboard"], queryFn: () => api<any>("/api/dashboard"), refetchInterval: 20_000 });
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorState error={q.error} retry={() => q.refetch()} />;
  const { stats: s, charts: c } = q.data;
  const hasTrust = c.trust_distribution.some((x: any) => x.count > 0);
  const hasTvS = c.trusted_vs_suspicious.some((x: any) => x.value > 0);
  return (
    <>
      <PageHeader title="Dashboard" subtitle="Live statistics from your datasets, detection runs and experiments." />
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="Total datasets" value={s.total_datasets} icon={<Database className="h-5 w-5" />} />
        <Stat label="Records processed" value={s.records_processed.toLocaleString()} icon={<Table2 className="h-5 w-5" />} />
        <Stat label="Suspicious records" value={s.suspicious_records.toLocaleString()} icon={<ShieldAlert className="h-5 w-5" />} tone="crit" />
        <Stat label="In quarantine" value={s.quarantined_records.toLocaleString()} icon={<AlertOctagon className="h-5 w-5" />} tone="warn" />
        <Stat label="Datasets awaiting review" value={s.awaiting_review} icon={<FileWarning className="h-5 w-5" />} tone="warn" />
        <Stat label="Data-quality issues" value={s.data_quality_issues} icon={<ListChecks className="h-5 w-5" />} tone="warn" />
        <Stat label="Models trained" value={s.models_trained} icon={<Boxes className="h-5 w-5" />} tone="ok" />
        <Stat label="Active experiments" value={s.active_experiments} icon={<FlaskConical className="h-5 w-5" />} />
      </div>
      <div className="mt-6 grid gap-4 lg:grid-cols-2">
        <ChartBox title="Trust-score distribution" empty={!hasTrust}>
          <ResponsiveContainer><BarChart data={c.trust_distribution}><CartesianGrid strokeDasharray="3 3" stroke="#DBEAFE" /><XAxis dataKey="range" fontSize={11} /><YAxis allowDecimals={false} fontSize={11} /><Tooltip /><Bar dataKey="count" name="Records" fill="#2563EB" radius={[4, 4, 0, 0]} /></BarChart></ResponsiveContainer>
        </ChartBox>
        <ChartBox title="Trusted vs suspicious records" empty={!hasTvS}>
          <ResponsiveContainer><PieChart><Pie data={c.trusted_vs_suspicious} dataKey="value" nameKey="name" innerRadius={50} outerRadius={85} paddingAngle={2}>{c.trusted_vs_suspicious.map((_: any, i: number) => <Cell key={i} fill={PIE[i % 4]} />)}</Pie><Tooltip /><Legend /></PieChart></ResponsiveContainer>
        </ChartBox>
        <ChartBox title="Detection-method results (records flagged)" empty={!c.detection_methods.some((x: any) => x.flagged > 0)}>
          <ResponsiveContainer><BarChart data={c.detection_methods} layout="vertical"><CartesianGrid strokeDasharray="3 3" stroke="#DBEAFE" /><XAxis type="number" allowDecimals={false} fontSize={11} /><YAxis type="category" dataKey="method" width={130} fontSize={11} /><Tooltip /><Bar dataKey="flagged" fill="#1E3A8A" radius={[0, 4, 4, 0]} /></BarChart></ResponsiveContainer>
        </ChartBox>
        <ChartBox title="Model accuracy: clean vs poisoned vs filtered" empty={!c.model_before_after.length}>
          <ResponsiveContainer><BarChart data={c.model_before_after}><CartesianGrid strokeDasharray="3 3" stroke="#DBEAFE" /><XAxis dataKey="experiment" fontSize={10} /><YAxis domain={[0, 1]} fontSize={11} /><Tooltip formatter={(v: number) => v?.toFixed(3)} /><Legend />
            <Bar dataKey="clean" fill="#1E3A8A" /><Bar dataKey="poisoned" fill="#DC2626" /><Bar dataKey="filtered" fill="#2563EB" /></BarChart></ResponsiveContainer>
        </ChartBox>
        <ChartBox title="Experiment outcomes" empty={!c.experiment_outcomes.length}>
          <ResponsiveContainer><BarChart data={c.experiment_outcomes}><CartesianGrid strokeDasharray="3 3" stroke="#DBEAFE" /><XAxis dataKey="status" fontSize={11} /><YAxis allowDecimals={false} fontSize={11} /><Tooltip /><Bar dataKey="count" radius={[4, 4, 0, 0]}>{c.experiment_outcomes.map((_: any, i: number) => <Cell key={i} fill={BLUES[i % 4]} />)}</Bar></BarChart></ResponsiveContainer>
        </ChartBox>
        <ChartBox title="Data-quality issues over time" empty={!c.quality_issues_over_time.length}>
          <ResponsiveContainer><LineChart data={c.quality_issues_over_time}><CartesianGrid strokeDasharray="3 3" stroke="#DBEAFE" /><XAxis dataKey="date" fontSize={11} /><YAxis allowDecimals={false} fontSize={11} /><Tooltip /><Line type="monotone" dataKey="issues" stroke="#2563EB" strokeWidth={2} dot /></LineChart></ResponsiveContainer>
        </ChartBox>
      </div>
      <div className="mt-6 grid gap-4 lg:grid-cols-2">
        <Card title="Recent alerts" right={<Link className="text-sm font-medium text-primary" to="/notifications">View all</Link>}>
          {!q.data.recent_alerts.length ? <Empty title="No alerts" hint="Alerts appear when pipelines, detections or integrity checks produce events." /> :
            <ul className="divide-y divide-line">{q.data.recent_alerts.map((a: any) => <li key={a.id} className="flex items-start justify-between gap-3 py-2 text-sm"><div><div className="font-medium">{a.title}</div><div className="text-muted">{a.body}</div></div><div className="text-right"><Badge value={a.level} /><div className="mt-1 text-xs text-muted">{fmtDate(a.created_at)}</div></div></li>)}</ul>}
        </Card>
        <Card title="Recent security events" right={<Activity className="h-4 w-4 text-primary" />}>
          {!q.data.recent_security_events.length ? <Empty title="No security events" hint="Failed logins, integrity failures and permission changes appear here for reviewers and admins." /> :
            <ul className="divide-y divide-line">{q.data.recent_security_events.map((e: any) => <li key={e.id} className="flex justify-between py-2 text-sm"><span className="font-mono text-xs">{e.action}</span><span className="text-xs text-muted">{fmtDate(e.ts)}</span></li>)}</ul>}
        </Card>
      </div>
    </>
  );
}
