"""CSV / PDF report exports. CSV cells are sanitized against spreadsheet formula injection."""
import csv
import io
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import log_event
from ..db import get_db
from ..deps import require
from ..models import (AuditEvent, Dataset, DatasetVersion, DetectionRun, DetectionResult, Experiment,
                      PipelineRun, QuarantinedRecord, RegisteredModel, TrainingRun, User)

router = APIRouter(prefix="/api/reports", tags=["reports"])
REPORTS = {"dataset-quality", "trust-scores", "anomaly-detection", "quarantine", "provenance", "model-training",
           "model-impact", "experiments", "audit-logs"}
GLOBAL_READ = ("admin", "reviewer", "viewer")


def _safe(v) -> str:
    s = "" if v is None else (f"{v:.4f}" if isinstance(v, float) else str(v))
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def _scope(q, user: User, col):
    return q if user.role in GLOBAL_READ else q.where(col.in_(select(Dataset.id).where(Dataset.owner_id == user.id)))


def build(db: Session, user: User, kind: str, dataset_id: str):
    def ds_filter(q, col):
        q = _scope(q, user, col)
        return q.where(col == dataset_id) if dataset_id else q

    if kind == "dataset-quality":
        runs = db.execute(ds_filter(select(PipelineRun).where(PipelineRun.status == "completed"), PipelineRun.dataset_id)
                          .order_by(PipelineRun.created_at.desc())).scalars().all()
        names = {d.id: d.name for d in db.execute(select(Dataset)).scalars()}
        cols = ["dataset", "run_at", "rows_before", "rows_after", "missing_cells", "duplicate_rows", "issue_count"]
        rows = [[names.get(r.dataset_id), r.finished_at, r.report.get("rows_before"), r.report.get("rows_after"),
                 r.report["quality"]["missing_cells"], r.report["quality"]["duplicate_rows"], r.report["quality"]["issue_count"]] for r in runs]
        return "Dataset Quality Report", cols, rows
    if kind in ("trust-scores", "anomaly-detection"):
        runs = db.execute(ds_filter(select(DetectionRun).where(DetectionRun.status == "completed"), DetectionRun.dataset_id)
                          .order_by(DetectionRun.created_at.desc()).limit(1 if dataset_id else 20)).scalars().all()
        if kind == "trust-scores":
            cols = ["run_id", "row", "trust_score", "category", "statistical_normality", "label_consistency", "provenance", "data_quality", "model_impact"]
        else:
            cols = ["run_id", "row", "iforest_score", "lof_score", "distribution_score", "category", "explanation"]
        rows = []
        for run in runs[:1] if not dataset_id else runs[:1]:
            for r in db.execute(select(DetectionResult).where(DetectionResult.run_id == run.id).order_by(DetectionResult.row_index).limit(50000)).scalars():
                if kind == "trust-scores":
                    rows.append([run.id[:8], r.row_index, r.trust_score, r.category, r.statistical_normality, r.label_consistency, r.provenance, r.data_quality, r.model_impact])
                else:
                    rows.append([run.id[:8], r.row_index, r.iforest_score, r.lof_score, r.distribution_score, r.category, "; ".join(r.explanation or [])])
        return ("Trust Score Report" if kind == "trust-scores" else "Anomaly Detection Report"), cols, rows
    if kind == "quarantine":
        q = ds_filter(select(QuarantinedRecord), QuarantinedRecord.dataset_id).order_by(QuarantinedRecord.created_at.desc())
        cols = ["id", "dataset_id", "row", "trust_score", "status", "reasons", "created_at"]
        return "Quarantine Report", cols, [[r.id[:8], r.dataset_id[:8], r.row_index, r.trust_score, r.status, "; ".join(r.reasons or []), r.created_at]
                                           for r in db.execute(q).scalars()]
    if kind == "provenance":
        q = ds_filter(select(DatasetVersion), DatasetVersion.dataset_id).order_by(DatasetVersion.dataset_id, DatasetVersion.version)
        names = {d.id: (d.name, d.source) for d in db.execute(select(Dataset)).scalars()}
        cols = ["dataset", "source", "version", "kind", "sha256", "rows", "transformation", "created_at"]
        return "Provenance Report", cols, [[names.get(v.dataset_id, ("", ""))[0], names.get(v.dataset_id, ("", ""))[1], v.version, v.kind,
                                            v.sha256, v.n_rows, v.transformation, v.created_at] for v in db.execute(q).scalars()]
    if kind == "model-training":
        q = ds_filter(select(RegisteredModel), RegisteredModel.dataset_id).order_by(RegisteredModel.created_at.desc())
        cols = ["model", "version", "type", "accuracy", "precision", "recall", "f1", "roc_auc", "sha256", "created_at"]
        return "Model Training Report", cols, [[m.name, m.version, m.model_type, m.metrics.get("accuracy"), m.metrics.get("precision"),
                                                m.metrics.get("recall"), m.metrics.get("f1"), m.metrics.get("roc_auc"), m.sha256, m.created_at]
                                               for m in db.execute(q).scalars()]
    if kind in ("model-impact", "experiments"):
        q = ds_filter(select(Experiment).where(Experiment.status == "completed"), Experiment.dataset_id).order_by(Experiment.created_at.desc())
        exps = db.execute(q).scalars().all()
        if kind == "model-impact":
            cols = ["experiment", "attack", "rate", "clean_acc", "poisoned_acc", "filtered_acc", "clean_f1", "poisoned_f1", "filtered_f1"]
            rows = []
            for e in exps:
                r = e.results
                f = r.get("filtered") or {}
                rows.append([e.name, e.attack, e.poison_rate, r["clean"]["accuracy"], r["poisoned"]["accuracy"], f.get("accuracy"),
                             r["clean"]["f1"], r["poisoned"]["f1"], f.get("f1")])
            return "Model Impact Report", cols, rows
        cols = ["experiment", "attack", "rate", "precision", "recall", "fpr", "f1", "roc_auc", "retention", "detection_time_s"]
        return "Poisoning Experiments Report", cols, [[e.name, e.attack, e.poison_rate] + [e.results["detection"].get(k) for k in
                ("precision", "recall", "false_positive_rate", "f1", "roc_auc", "retention", "detection_time_s")] for e in exps]
    if kind == "audit-logs":
        if user.role != "admin":
            raise HTTPException(403, "Administrator access required")
        evs = db.execute(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(5000)).scalars().all()
        cols = ["id", "time", "actor", "action", "resource", "resource_id", "security", "ip", "hash"]
        return "Audit Log Report", cols, [[e.id, e.ts, e.actor_id, e.action, e.resource_type, e.resource_id, e.is_security, e.ip, e.hash[:16]] for e in evs]
    raise HTTPException(404, "Unknown report")


def _pdf(title: str, cols, rows) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=24, rightMargin=24, topMargin=24, bottomMargin=24)
    st = getSampleStyleSheet()
    cell = st["BodyText"]
    cell.fontSize = 7
    cell.leading = 8.5
    data = [[Paragraph(f"<b>{c}</b>", cell) for c in cols]]
    from xml.sax.saxutils import escape
    for r in rows[:1500]:
        data.append([Paragraph(escape(("" if v is None else (f"{v:.4f}" if isinstance(v, float) else str(v)))[:160]), cell) for v in r])
    t = Table(data, repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DBEAFE")),
                           ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#BFDBFE")),
                           ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    doc.build([Paragraph(f"TrustGuard AI — {escape(title)}", st["Title"]),
               Paragraph(f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · {len(rows)} row(s)"
                         + (" (first 1500 shown)" if len(rows) > 1500 else ""), st["Normal"]), Spacer(1, 10), t])
    return buf.getvalue()


@router.get("/{kind}")
def report(kind: str, format: str = Query("csv", pattern="^(csv|pdf)$"), dataset_id: str = "",
           user: User = Depends(require("report:read")), db: Session = Depends(get_db)):
    if kind not in REPORTS:
        raise HTTPException(404, "Unknown report")
    title, cols, rows = build(db, user, kind, dataset_id)
    log_event(db, "report.exported", actor_id=user.id, resource_type="report", resource_id=kind, detail={"format": format})
    if format == "csv":
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(cols)
        for r in rows:
            w.writerow([_safe(v) for v in r])
        return Response(out.getvalue(), media_type="text/csv", headers={
            "Content-Disposition": f'attachment; filename="trustguard_{kind}.csv"', "X-Content-Type-Options": "nosniff"})
    return Response(_pdf(title, cols, rows), media_type="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="trustguard_{kind}.pdf"', "X-Content-Type-Options": "nosniff"})
