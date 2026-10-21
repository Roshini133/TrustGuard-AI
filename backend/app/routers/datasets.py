import io
import re

import numpy as np
import pandas as pd
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sklearn.datasets import make_classification
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..audit import log_event, notify
from ..config import get_settings
from ..db import get_db
from ..deps import current_user, require
from ..ml import pipeline as pl
from ..models import (Dataset, DatasetVersion, Experiment, LineageEdge, PipelineRun, RegisteredModel, User)
from ..ratelimit import client_ip
from ..security import sha256_bytes
from ..storage import get_storage
from ..tasks import store_artifact, load_version_df
from .. import jobs

router = APIRouter(prefix="/api/datasets", tags=["datasets"])

READ_ALL_ROLES = {"admin", "reviewer", "viewer"}


def can_read(user: User, ds: Dataset) -> bool:
    return ds.owner_id == user.id or user.role in READ_ALL_ROLES


def can_write(user: User, ds: Dataset) -> bool:
    return ds.owner_id == user.id or user.role == "admin"


def get_ds(db: Session, ds_id: str, user: User, write: bool = False) -> Dataset:
    ds = db.get(Dataset, ds_id)
    if not ds or not (can_write(user, ds) if write else can_read(user, ds)):
        raise HTTPException(404, "Dataset not found")   # 404 avoids revealing existence
    return ds


def ds_out(ds: Dataset, db: Session | None = None) -> dict:
    last = max(ds.versions, key=lambda v: v.version) if ds.versions else None
    return {"id": ds.id, "name": ds.name, "description": ds.description, "source": ds.source,
            "label_column": ds.label_column, "status": ds.status, "created_at": ds.created_at,
            "owner_id": ds.owner_id, "n_versions": len(ds.versions),
            "n_rows": last.n_rows if last else 0, "n_cols": last.n_cols if last else 0,
            "sha256": next((v.sha256 for v in ds.versions if v.kind == "raw"), None)}


def ver_out(v: DatasetVersion) -> dict:
    return {"id": v.id, "version": v.version, "kind": v.kind, "sha256": v.sha256, "size_bytes": v.size_bytes,
            "n_rows": v.n_rows, "n_cols": v.n_cols, "parent_version_id": v.parent_version_id,
            "transformation": v.transformation, "created_at": v.created_at}


def _safe_name(n: str) -> str:
    return re.sub(r"[^A-Za-z0-9._ -]", "_", n)[:120]


def _create_raw(db: Session, ds: Dataset, data: bytes, ext: str, df: pd.DataFrame) -> DatasetVersion:
    key = f"datasets/{ds.id}/v1_raw{ext}"
    h = store_artifact(db, key, data, "dataset_raw")
    v = DatasetVersion(dataset_id=ds.id, version=1, kind="raw", artifact_key=key, sha256=h, size_bytes=len(data),
                       n_rows=len(df), n_cols=df.shape[1], transformation="upload")
    db.add(v)
    db.flush()
    return v


@router.post("", status_code=201)
async def upload(request: Request, file: UploadFile = File(...), name: str = Form(""), description: str = Form(""),
                 source: str = Form(""), label_column: str = Form(""),
                 user: User = Depends(require("dataset:write")), db: Session = Depends(get_db)):
    s = get_settings()
    fname = file.filename or ""
    ext = "." + fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
    if ext not in pl.ALLOWED_EXT:
        raise HTTPException(422, "Only .csv and .xlsx files are supported.")
    data = await file.read(s.MAX_UPLOAD_MB * 1024 * 1024 + 1)
    if len(data) > s.MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(413, f"File exceeds {s.MAX_UPLOAD_MB} MB limit.")
    if not data:
        raise HTTPException(422, "File is empty.")
    if ext == ".xlsx" and not data.startswith(b"PK"):
        raise HTTPException(422, "File content does not match .xlsx format.")
    if ext == ".csv" and b"\x00" in data[:4096]:
        raise HTTPException(422, "File content does not look like CSV text.")
    try:
        df = pl.load_dataframe(data, fname)
    except pl.DatasetError as e:
        raise HTTPException(422, str(e))
    label = label_column.strip() or None
    if label and label not in df.columns:
        raise HTTPException(422, f"Label column '{label}' not found in file.")
    ds = Dataset(name=(name.strip() or _safe_name(fname.rsplit('.', 1)[0]))[:255], description=description[:2000],
                 source=source[:255], owner_id=user.id, label_column=label)
    db.add(ds)
    db.flush()
    v = _create_raw(db, ds, data, ext, df)
    db.commit()
    log_event(db, "dataset.uploaded", actor_id=user.id, resource_type="dataset", resource_id=ds.id,
              detail={"sha256": v.sha256, "rows": len(df)}, ip=client_ip(request))
    return {**ds_out(ds), "version": ver_out(v)}


class SampleIn(BaseModel):
    rows: int = Field(600, ge=100, le=20000)
    features: int = Field(8, ge=3, le=40)
    name: str = "sample-dataset"


@router.post("/sample", status_code=201)
def create_sample(body: SampleIn, request: Request, user: User = Depends(require("dataset:write")),
                  db: Session = Depends(get_db)):
    X, y = make_classification(n_samples=body.rows, n_features=body.features, n_informative=max(2, body.features // 2),
                               n_redundant=1, class_sep=1.5, random_state=7)
    df = pd.DataFrame(X, columns=[f"feature_{i+1}" for i in range(body.features)]).round(4)
    df["label"] = y
    rng = np.random.default_rng(1)
    for c in df.columns[:2]:
        df.loc[rng.choice(len(df), max(1, len(df) // 100), replace=False), c] = np.nan
    df = pd.concat([df, df.iloc[:3]], ignore_index=True)
    data = pl.to_csv_bytes(df)
    ds = Dataset(name=body.name[:255], description="Synthetic classification sample with seeded missing values and duplicates.",
                 source="TrustGuard sample generator", owner_id=user.id, label_column="label")
    db.add(ds)
    db.flush()
    v = _create_raw(db, ds, data, ".csv", df)
    db.commit()
    log_event(db, "dataset.sample_created", actor_id=user.id, resource_type="dataset", resource_id=ds.id, ip=client_ip(request))
    return {**ds_out(ds), "version": ver_out(v)}


@router.get("")
def list_datasets(search: str = "", status: str = "", page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
                  user: User = Depends(require("dataset:read")), db: Session = Depends(get_db)):
    q = select(Dataset)
    if user.role not in READ_ALL_ROLES:
        q = q.where(Dataset.owner_id == user.id)
    if search:
        like = f"%{search.strip()}%"
        q = q.where(or_(Dataset.name.ilike(like), Dataset.source.ilike(like), Dataset.description.ilike(like)))
    if status:
        q = q.where(Dataset.status == status)
    total = db.execute(select(func.count()).select_from(q.subquery())).scalar()
    rows = db.execute(q.order_by(Dataset.created_at.desc()).offset((page - 1) * page_size).limit(page_size)).scalars().all()
    return {"items": [ds_out(d) for d in rows], "total": total, "page": page, "page_size": page_size}


@router.get("/{ds_id}")
def get_dataset(ds_id: str, user: User = Depends(require("dataset:read")), db: Session = Depends(get_db)):
    ds = get_ds(db, ds_id, user)
    return {**ds_out(ds), "versions": [ver_out(v) for v in sorted(ds.versions, key=lambda v: v.version)]}


@router.get("/{ds_id}/preview")
def preview(ds_id: str, version_id: str = "", rows: int = Query(20, ge=1, le=200),
            user: User = Depends(require("dataset:read")), db: Session = Depends(get_db)):
    ds = get_ds(db, ds_id, user)
    v = db.get(DatasetVersion, version_id) if version_id else max(ds.versions, key=lambda x: x.version)
    if not v or v.dataset_id != ds.id:
        raise HTTPException(404, "Version not found")
    df, ok = load_version_df(db, v)
    head = df.head(rows).astype(object).where(df.head(rows).notna(), None)
    return {"columns": list(df.columns), "rows": head.values.tolist(), "total_rows": len(df), "integrity_ok": ok}


@router.get("/{ds_id}/download")
def download(ds_id: str, request: Request, version_id: str = "", user: User = Depends(require("dataset:read")),
             db: Session = Depends(get_db)):
    ds = get_ds(db, ds_id, user, write=True)   # owner or admin only
    v = db.get(DatasetVersion, version_id) if version_id else max(ds.versions, key=lambda x: x.version)
    if not v or v.dataset_id != ds.id:
        raise HTTPException(404, "Version not found")
    data = get_storage().get(v.artifact_key)
    if sha256_bytes(data) != v.sha256:
        log_event(db, "integrity.hash_mismatch", actor_id=user.id, resource_type="dataset_version", resource_id=v.id, security=True)
        raise HTTPException(409, "Integrity check failed; download blocked.")
    log_event(db, "dataset.downloaded", actor_id=user.id, resource_type="dataset", resource_id=ds.id, ip=client_ip(request))
    ext = ".xlsx" if v.artifact_key.endswith(".xlsx") else ".csv"
    media = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" if ext == ".xlsx" else "text/csv"
    return Response(data, media_type=media, headers={
        "Content-Disposition": f'attachment; filename="{_safe_name(ds.name)}_v{v.version}{ext}"',
        "X-Content-Type-Options": "nosniff"})


@router.post("/{ds_id}/verify-integrity")
def verify_integrity(ds_id: str, user: User = Depends(require("dataset:read")), db: Session = Depends(get_db)):
    ds = get_ds(db, ds_id, user)
    out = []
    for v in sorted(ds.versions, key=lambda x: x.version):
        try:
            ok = sha256_bytes(get_storage().get(v.artifact_key)) == v.sha256
        except Exception:
            ok = False
        out.append({"version_id": v.id, "version": v.version, "kind": v.kind, "sha256": v.sha256, "verified": ok})
        if not ok:
            log_event(db, "integrity.hash_mismatch", actor_id=user.id, resource_type="dataset_version", resource_id=v.id, security=True)
            notify(db, "Integrity failure", f"Version {v.version} of '{ds.name}' failed SHA-256 verification.", "critical")
    return {"dataset_id": ds.id, "all_verified": all(o["verified"] for o in out), "versions": out}


@router.get("/{ds_id}/lineage")
def lineage(ds_id: str, user: User = Depends(require("dataset:read")), db: Session = Depends(get_db)):
    ds = get_ds(db, ds_id, user)
    edges = db.execute(select(LineageEdge).where(LineageEdge.dataset_id == ds.id).order_by(LineageEdge.created_at)).scalars().all()
    models = db.execute(select(RegisteredModel).where(RegisteredModel.dataset_id == ds.id)).scalars().all()
    exps = db.execute(select(Experiment).where(Experiment.dataset_id == ds.id)).scalars().all()
    return {
        "dataset": ds_out(ds),
        "nodes": [{"id": v.id, "type": "version", "label": f"v{v.version} ({v.kind})", "sha256": v.sha256,
                   "n_rows": v.n_rows, "created_at": v.created_at, "transformation": v.transformation}
                  for v in sorted(ds.versions, key=lambda x: x.version)]
                 + [{"id": m.id, "type": "model", "label": f"{m.name} v{m.version}", "sha256": m.sha256, "created_at": m.created_at} for m in models]
                 + [{"id": e.id, "type": "experiment", "label": e.name, "created_at": e.created_at} for e in exps],
        "edges": [{"from": e.src_id, "to": e.dst_id, "operation": e.operation, "created_at": e.created_at} for e in edges],
        "source": {"declared_source": ds.source, "uploaded_by": ds.owner_id},
    }


@router.post("/{ds_id}/pipeline", status_code=202)
def start_pipeline(ds_id: str, user: User = Depends(require("pipeline:run")), db: Session = Depends(get_db)):
    ds = get_ds(db, ds_id, user, write=True)
    raw = next((v for v in ds.versions if v.kind == "raw"), None)
    run = PipelineRun(dataset_id=ds.id, version_id=raw.id, created_by=user.id)
    db.add(run)
    db.commit()
    log_event(db, "pipeline.started", actor_id=user.id, resource_type="dataset", resource_id=ds.id)
    jobs.enqueue("pipeline", run.id)
    return {"run_id": run.id, "status": "queued"}


def run_out(r) -> dict:
    return {c.name: getattr(r, c.name) for c in r.__table__.columns}


@router.get("/{ds_id}/pipeline-runs")
def pipeline_runs(ds_id: str, user: User = Depends(require("dataset:read")), db: Session = Depends(get_db)):
    ds = get_ds(db, ds_id, user)
    rs = db.execute(select(PipelineRun).where(PipelineRun.dataset_id == ds.id).order_by(PipelineRun.created_at.desc())).scalars().all()
    return {"items": [run_out(r) for r in rs]}
