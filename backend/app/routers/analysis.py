"""Detection, quarantine, training, model registry, experiments."""
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import jobs
from ..audit import log_event, notify
from ..db import get_db
from ..deps import has_perm, require
from ..ml.detection import merged_config
from ..ml.poison import ATTACKS
from ..ml.training import MODEL_TYPES
from ..models import (Dataset, DatasetVersion, DetectionResult, DetectionRun, Experiment, ExperimentGroundTruth,
                      QuarantinedRecord, RegisteredModel, ReviewDecision, TrainingRun, User)
from ..ratelimit import client_ip
from ..security import sha256_bytes
from ..storage import get_storage
from ..tasks import create_version, latest_analysis_version, load_version_df
from .datasets import get_ds, run_out, can_read

router = APIRouter(prefix="/api", tags=["analysis"])


# ---------------- detection ----------------
class DetectIn(BaseModel):
    version_id: str | None = None
    weights: dict[str, float] | None = None
    high_trust_min: float | None = Field(None, ge=0, le=100)
    review_min: float | None = Field(None, ge=0, le=100)
    contamination: float | None = Field(None, gt=0, le=0.5)
    anomaly_flag: float | None = Field(None, ge=0, le=1)


@router.post("/datasets/{ds_id}/detect", status_code=202)
def start_detection(ds_id: str, body: DetectIn, user: User = Depends(require("detect:run")), db: Session = Depends(get_db)):
    ds = get_ds(db, ds_id, user, write=True)
    cfg = {k: v for k, v in body.model_dump().items() if v is not None and k != "version_id"}
    try:
        merged_config(cfg)
    except ValueError as e:
        raise HTTPException(422, str(e))
    v = db.get(DatasetVersion, body.version_id) if body.version_id else latest_analysis_version(db, ds.id)
    if not v or v.dataset_id != ds.id:
        raise HTTPException(404, "Version not found")
    run = DetectionRun(dataset_id=ds.id, version_id=v.id, config=cfg, created_by=user.id)
    db.add(run)
    db.commit()
    log_event(db, "detection.started", actor_id=user.id, resource_type="dataset", resource_id=ds.id)
    jobs.enqueue("detection", run.id)
    return {"run_id": run.id, "status": "queued"}


@router.get("/datasets/{ds_id}/detection-runs")
def detection_runs(ds_id: str, user: User = Depends(require("dataset:read")), db: Session = Depends(get_db)):
    ds = get_ds(db, ds_id, user)
    rs = db.execute(select(DetectionRun).where(DetectionRun.dataset_id == ds.id).order_by(DetectionRun.created_at.desc())).scalars().all()
    return {"items": [run_out(r) for r in rs]}


def _run_for(db, run_id, user) -> DetectionRun:
    run = db.get(DetectionRun, run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    get_ds(db, run.dataset_id, user)
    return run


@router.get("/detection-runs/{run_id}")
def detection_run(run_id: str, user: User = Depends(require("dataset:read")), db: Session = Depends(get_db)):
    return run_out(_run_for(db, run_id, user))


@router.get("/detection-runs/{run_id}/results")
def detection_results(run_id: str, category: str = "", sort: str = "trust_asc", page: int = Query(1, ge=1),
                      page_size: int = Query(25, ge=1, le=200), user: User = Depends(require("dataset:read")),
                      db: Session = Depends(get_db)):
    run = _run_for(db, run_id, user)
    q = select(DetectionResult).where(DetectionResult.run_id == run.id)
    if category:
        q = q.where(DetectionResult.category == category)
    total = db.execute(select(func.count()).select_from(q.subquery())).scalar()
    order = {"trust_asc": DetectionResult.trust_score.asc(), "trust_desc": DetectionResult.trust_score.desc(),
             "row": DetectionResult.row_index.asc()}.get(sort, DetectionResult.trust_score.asc())
    rows = db.execute(q.order_by(order, DetectionResult.row_index).offset((page - 1) * page_size).limit(page_size)).scalars().all()
    return {"items": [{c.name: getattr(r, c.name) for c in r.__table__.columns if c.name != "run_id"} for r in rows],
            "total": total, "page": page, "page_size": page_size}


@router.get("/datasets/{ds_id}/trust-histogram")
def trust_histogram(ds_id: str, user: User = Depends(require("dataset:read")), db: Session = Depends(get_db)):
    ds = get_ds(db, ds_id, user)
    run = db.execute(select(DetectionRun).where(DetectionRun.dataset_id == ds.id, DetectionRun.status == "completed")
                     .order_by(DetectionRun.created_at.desc())).scalars().first()
    if not run:
        return {"bins": [], "run_id": None}
    scores = db.execute(select(DetectionResult.trust_score).where(DetectionResult.run_id == run.id)).scalars().all()
    bins = [0] * 10
    for s in scores:
        if s is not None:
            bins[min(9, int(s // 10))] += 1
    return {"run_id": run.id, "bins": [{"range": f"{i*10}-{i*10+10}", "count": c} for i, c in enumerate(bins)]}


# ---------------- quarantine ----------------
def _q_out(q: QuarantinedRecord, ds_name: str | None = None) -> dict:
    return {"id": q.id, "dataset_id": q.dataset_id, "dataset_name": ds_name, "run_id": q.run_id, "row_index": q.row_index,
            "trust_score": q.trust_score, "reasons": q.reasons, "status": q.status, "created_at": q.created_at}


@router.get("/quarantine")
def list_quarantine(status: str = "", dataset_id: str = "", page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100),
                    user: User = Depends(require("dataset:read")), db: Session = Depends(get_db)):
    q = select(QuarantinedRecord, Dataset.name).join(Dataset, Dataset.id == QuarantinedRecord.dataset_id)
    if user.role not in ("admin", "reviewer", "viewer"):
        q = q.where(Dataset.owner_id == user.id)
    if status:
        q = q.where(QuarantinedRecord.status == status)
    if dataset_id:
        q = q.where(QuarantinedRecord.dataset_id == dataset_id)
    total = db.execute(select(func.count()).select_from(q.subquery())).scalar()
    rows = db.execute(q.order_by(QuarantinedRecord.trust_score.asc(), QuarantinedRecord.created_at.desc())
                      .offset((page - 1) * page_size).limit(page_size)).all()
    return {"items": [_q_out(r, n) for r, n in rows], "total": total, "page": page, "page_size": page_size}


@router.get("/quarantine/{rid}")
def quarantine_detail(rid: str, user: User = Depends(require("dataset:read")), db: Session = Depends(get_db)):
    rec = db.get(QuarantinedRecord, rid)
    if not rec:
        raise HTTPException(404, "Record not found")
    ds = get_ds(db, rec.dataset_id, user)
    run = db.get(DetectionRun, rec.run_id)
    df, _ = load_version_df(db, db.get(DatasetVersion, run.version_id))
    row = df.iloc[rec.row_index].astype(object).where(df.iloc[rec.row_index].notna(), None).to_dict() if rec.row_index < len(df) else {}
    res = db.execute(select(DetectionResult).where(DetectionResult.run_id == rec.run_id, DetectionResult.row_index == rec.row_index)).scalar_one_or_none()
    decs = db.execute(select(ReviewDecision).where(ReviewDecision.record_id == rec.id).order_by(ReviewDecision.created_at)).scalars().all()
    return {**_q_out(rec, ds.name), "row": row,
            "components": None if not res else {k: getattr(res, k) for k in (
                "statistical_normality", "label_consistency", "provenance", "data_quality", "model_impact",
                "iforest_score", "lof_score", "distribution_score", "category")},
            "decisions": [{"id": d.id, "reviewer_id": d.reviewer_id, "decision": d.decision, "notes": d.notes, "created_at": d.created_at} for d in decs]}


class DecisionIn(BaseModel):
    decision: str = Field(pattern="^(approve|reject|investigate|release)$")
    notes: str = Field("", max_length=2000)


_STATUS = {"approve": "approved", "reject": "rejected", "investigate": "investigating", "release": "released"}


@router.post("/quarantine/{rid}/decision")
def decide(rid: str, body: DecisionIn, request: Request, user: User = Depends(require("quarantine:review")),
           db: Session = Depends(get_db)):
    rec = db.get(QuarantinedRecord, rid)
    if not rec:
        raise HTTPException(404, "Record not found")
    get_ds(db, rec.dataset_id, user)
    if body.decision == "release":
        if not has_perm(user, "quarantine:release"):
            log_event(db, "quarantine.release_denied", actor_id=user.id, resource_type="quarantine", resource_id=rid, security=True)
            raise HTTPException(403, "Only reviewers and administrators can release quarantined records.")
        if rec.status != "approved":
            raise HTTPException(409, "A record must be approved before it can be released.")
    if body.decision in ("reject", "release") and not body.notes.strip():
        raise HTTPException(422, "Review notes are required for this decision.")
    rec.status = _STATUS[body.decision]
    db.add(ReviewDecision(record_id=rec.id, reviewer_id=user.id, decision=body.decision, notes=body.notes.strip()))
    db.commit()
    log_event(db, f"quarantine.{body.decision}", actor_id=user.id, resource_type="quarantine", resource_id=rid,
              detail={"row_index": rec.row_index}, ip=client_ip(request))
    return _q_out(rec)


@router.post("/datasets/{ds_id}/apply-filter", status_code=201)
def apply_filter(ds_id: str, user: User = Depends(require("pipeline:run")), db: Session = Depends(get_db)):
    """Create a new filtered version excluding quarantined/rejected/investigating records. Raw/cleaned versions are untouched."""
    ds = get_ds(db, ds_id, user, write=True)
    run = db.execute(select(DetectionRun).where(DetectionRun.dataset_id == ds.id, DetectionRun.status == "completed")
                     .order_by(DetectionRun.created_at.desc())).scalars().first()
    if not run:
        raise HTTPException(409, "Run detection first.")
    src = db.get(DatasetVersion, run.version_id)
    drop = set(db.execute(select(QuarantinedRecord.row_index).where(
        QuarantinedRecord.run_id == run.id, QuarantinedRecord.status.in_(("quarantined", "rejected", "investigating")))).scalars())
    df, ok = load_version_df(db, src)
    if not ok:
        raise HTTPException(409, "Integrity check failed.")
    filtered = df.drop(index=[i for i in drop if i < len(df)]).reset_index(drop=True)
    v = create_version(db, ds, filtered, "filtered", src, f"filter:quarantine({len(drop)} removed)")
    db.commit()
    log_event(db, "dataset.filtered", actor_id=user.id, resource_type="dataset", resource_id=ds.id, detail={"removed": len(drop)})
    return {"version_id": v.id, "version": v.version, "rows_removed": len(drop), "rows_kept": len(filtered)}


# ---------------- training & registry ----------------
class TrainIn(BaseModel):
    model_config = {"protected_namespaces": ()}
    model_type: str
    target: str | None = None
    version_id: str | None = None


@router.post("/datasets/{ds_id}/train", status_code=202)
def train(ds_id: str, body: TrainIn, user: User = Depends(require("model:train")), db: Session = Depends(get_db)):
    ds = get_ds(db, ds_id, user, write=True)
    if body.model_type not in MODEL_TYPES:
        raise HTTPException(422, f"model_type must be one of {', '.join(MODEL_TYPES)}")
    target = body.target or ds.label_column
    if not target:
        raise HTTPException(422, "A target column is required.")
    v = db.get(DatasetVersion, body.version_id) if body.version_id else latest_analysis_version(db, ds.id)
    if not v or v.dataset_id != ds.id:
        raise HTTPException(404, "Version not found")
    run = TrainingRun(dataset_id=ds.id, version_id=v.id, model_type=body.model_type, target=target, created_by=user.id)
    db.add(run)
    db.commit()
    jobs.enqueue("training", run.id)
    return {"run_id": run.id, "status": "queued"}


@router.get("/training-runs")
def training_runs(dataset_id: str = "", user: User = Depends(require("dataset:read")), db: Session = Depends(get_db)):
    q = select(TrainingRun, Dataset.name).join(Dataset, Dataset.id == TrainingRun.dataset_id)
    if user.role not in ("admin", "reviewer", "viewer"):
        q = q.where(Dataset.owner_id == user.id)
    if dataset_id:
        q = q.where(TrainingRun.dataset_id == dataset_id)
    rows = db.execute(q.order_by(TrainingRun.created_at.desc()).limit(100)).all()
    return {"items": [{**run_out(r), "dataset_name": n} for r, n in rows]}


def _m_out(m: RegisteredModel) -> dict:
    return {"id": m.id, "name": m.name, "version": m.version, "model_type": m.model_type, "dataset_id": m.dataset_id,
            "dataset_version_id": m.version_id, "sha256": m.sha256, "metrics": m.metrics, "created_at": m.created_at}


@router.get("/models")
def list_models(user: User = Depends(require("dataset:read")), db: Session = Depends(get_db)):
    q = select(RegisteredModel)
    if user.role not in ("admin", "reviewer", "viewer"):
        q = q.where(RegisteredModel.dataset_id.in_(select(Dataset.id).where(Dataset.owner_id == user.id)))
    return {"items": [_m_out(m) for m in db.execute(q.order_by(RegisteredModel.created_at.desc())).scalars()]}


@router.post("/models/{mid}/verify")
def verify_model(mid: str, user: User = Depends(require("dataset:read")), db: Session = Depends(get_db)):
    m = db.get(RegisteredModel, mid)
    if not m:
        raise HTTPException(404, "Model not found")
    get_ds(db, m.dataset_id, user)
    ok = sha256_bytes(get_storage().get(m.artifact_key)) == m.sha256
    if not ok:
        log_event(db, "integrity.model_hash_mismatch", actor_id=user.id, resource_type="model", resource_id=m.id, security=True)
    return {"model_id": m.id, "sha256": m.sha256, "verified": ok}


# ---------------- experiments ----------------
class ExperimentIn(BaseModel):
    model_config = {"protected_namespaces": ()}
    dataset_id: str
    name: str = Field(min_length=2, max_length=255)
    attack: str
    poison_rate: float = Field(0.1, gt=0, le=0.5)
    model_type: str = "random_forest"


def _e_out(e: Experiment) -> dict:
    return {c.name: getattr(e, c.name) for c in e.__table__.columns}


@router.post("/experiments", status_code=202)
def create_experiment(body: ExperimentIn, user: User = Depends(require("experiment:run")), db: Session = Depends(get_db)):
    ds = get_ds(db, body.dataset_id, user, write=True)
    if body.attack not in ATTACKS:
        raise HTTPException(422, f"attack must be one of {', '.join(ATTACKS)}")
    if body.model_type not in MODEL_TYPES:
        raise HTTPException(422, f"model_type must be one of {', '.join(MODEL_TYPES)}")
    if not ds.label_column:
        raise HTTPException(422, "Dataset needs a label column for experiments.")
    e = Experiment(dataset_id=ds.id, name=body.name, attack=body.attack, poison_rate=body.poison_rate,
                   model_type=body.model_type, created_by=user.id)
    db.add(e)
    db.commit()
    log_event(db, "experiment.started", actor_id=user.id, resource_type="experiment", resource_id=e.id,
              detail={"attack": body.attack, "rate": body.poison_rate})
    jobs.enqueue("experiment", e.id)
    return {"experiment_id": e.id, "status": "queued"}


@router.get("/experiments")
def list_experiments(user: User = Depends(require("dataset:read")), db: Session = Depends(get_db)):
    q = select(Experiment, Dataset.name).join(Dataset, Dataset.id == Experiment.dataset_id)
    if user.role not in ("admin", "reviewer", "viewer"):
        q = q.where(Dataset.owner_id == user.id)
    rows = db.execute(q.order_by(Experiment.created_at.desc()).limit(100)).all()
    return {"items": [{**_e_out(e), "dataset_name": n} for e, n in rows]}


@router.get("/experiments/{eid}")
def get_experiment(eid: str, user: User = Depends(require("dataset:read")), db: Session = Depends(get_db)):
    e = db.get(Experiment, eid)
    if not e:
        raise HTTPException(404, "Experiment not found")
    get_ds(db, e.dataset_id, user)
    return _e_out(e)


@router.get("/experiments/{eid}/ground-truth")
def ground_truth_summary(eid: str, user: User = Depends(require("admin:ground_truth")), db: Session = Depends(get_db)):
    gt = db.execute(select(ExperimentGroundTruth).where(ExperimentGroundTruth.experiment_id == eid)).scalar_one_or_none()
    if not gt:
        raise HTTPException(404, "Not found")
    log_event(db, "experiment.ground_truth_viewed", actor_id=user.id, resource_type="experiment", resource_id=eid, security=True)
    return {"experiment_id": eid, "n_poisoned": gt.n_poisoned}
