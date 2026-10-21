"""Background job bodies. Used by Celery workers, an in-process thread pool, or synchronously (tests)."""
import io
import logging
import time
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from sqlalchemy import func, select

from .audit import log_event, notify
from .db import SessionLocal
from .ml import detection as det
from .ml import pipeline as pl
from .ml import poison as po
from .ml import training as tr
from .models import (Dataset, DatasetVersion, DetectionResult, DetectionRun, Experiment, ExperimentGroundTruth,
                     LineageEdge, PipelineRun, QuarantinedRecord, RegisteredModel, TrainingRun, ArtifactMeta)
from .security import sha256_bytes
from .storage import get_storage

log = logging.getLogger("trustguard.tasks")


def _now():
    return datetime.now(timezone.utc)


def store_artifact(db, key: str, data: bytes, kind: str) -> str:
    get_storage().put(key, data)
    h = sha256_bytes(data)
    db.add(ArtifactMeta(key=key, kind=kind, sha256=h, size_bytes=len(data)))
    return h


def load_version_df(db, version: DatasetVersion) -> tuple[pd.DataFrame, bool]:
    """Returns (df, integrity_ok). Integrity is verified against the SHA-256 recorded at creation."""
    data = get_storage().get(version.artifact_key)
    ok = sha256_bytes(data) == version.sha256
    if version.artifact_key.endswith(".xlsx"):
        df = pd.read_excel(io.BytesIO(data), engine="openpyxl")
    else:
        df = pd.read_csv(io.BytesIO(data))
    df.columns = [str(c).strip() for c in df.columns]
    return df, ok


def next_version_no(db, dataset_id: str) -> int:
    return (db.execute(select(func.max(DatasetVersion.version)).where(DatasetVersion.dataset_id == dataset_id)).scalar() or 0) + 1


def create_version(db, ds: Dataset, df: pd.DataFrame, kind: str, parent: DatasetVersion | None, transformation: str) -> DatasetVersion:
    no = next_version_no(db, ds.id)
    data = pl.to_csv_bytes(df)
    key = f"datasets/{ds.id}/v{no}_{kind}.csv"
    h = store_artifact(db, key, data, f"dataset_{kind}")
    v = DatasetVersion(dataset_id=ds.id, version=no, kind=kind, artifact_key=key, sha256=h, size_bytes=len(data),
                       n_rows=len(df), n_cols=df.shape[1], parent_version_id=parent.id if parent else None,
                       transformation=transformation)
    db.add(v)
    db.flush()
    if parent:
        db.add(LineageEdge(dataset_id=ds.id, src_type="version", src_id=parent.id, dst_type="version", dst_id=v.id,
                           operation=transformation))
    return v


def latest_analysis_version(db, dataset_id: str) -> DatasetVersion:
    q = select(DatasetVersion).where(DatasetVersion.dataset_id == dataset_id, DatasetVersion.kind.in_(("raw", "cleaned"))
                                     ).order_by(DatasetVersion.version.desc())
    return db.execute(q).scalars().first()


# ---------------- pipeline ----------------
def run_pipeline(run_id: str):
    db = SessionLocal()
    t0 = time.perf_counter()
    try:
        run = db.get(PipelineRun, run_id)
        ds = db.get(Dataset, run.dataset_id)
        run.status = "running"
        ds.status = "processing"
        db.commit()
        raw = db.get(DatasetVersion, run.version_id)
        df, ok = load_version_df(db, raw)
        if not ok:
            log_event(db, "integrity.hash_mismatch", resource_type="dataset_version", resource_id=raw.id, security=True)
            notify(db, "Integrity failure", f"SHA-256 mismatch for dataset '{ds.name}'", "critical")
            raise RuntimeError("Dataset integrity verification failed (SHA-256 mismatch).")
        report = pl.quality_report(df, ds.label_column)
        cleaned, tlog = pl.clean(df, ds.label_column)
        v = create_version(db, ds, cleaned, "cleaned", raw, "pipeline:clean")
        run.report = {"quality": report, "transformations": tlog, "rows_before": len(df), "rows_after": len(cleaned)}
        run.output_version_id = v.id
        run.status = "completed"
        run.finished_at = _now()
        ds.status = "processed"
        db.commit()
        if report["issue_count"]:
            notify(db, "Data-quality issues found", f"'{ds.name}': {report['issue_count']} issue type(s) detected.", "warning")
        log_event(db, "pipeline.completed", actor_id=run.created_by, resource_type="dataset", resource_id=ds.id,
                  detail={"seconds": round(time.perf_counter() - t0, 2)})
    except Exception as e:
        db.rollback()
        run = db.get(PipelineRun, run_id)
        run.status, run.error, run.finished_at = "failed", f"{type(e).__name__}: {e}"[:1000], _now()
        ds = db.get(Dataset, run.dataset_id)
        ds.status = "failed"
        db.commit()
        log.exception("pipeline failed")
        notify(db, "Pipeline failed", f"Dataset '{ds.name}': {str(e)[:200]}", "critical")
    finally:
        db.close()


# ---------------- detection ----------------
QUARANTINE_CATEGORIES = ("highly_suspicious", "invalid")


def run_detection_job(run_id: str):
    db = SessionLocal()
    try:
        run = db.get(DetectionRun, run_id)
        ds = db.get(Dataset, run.dataset_id)
        run.status = "running"
        db.commit()
        version = db.get(DatasetVersion, run.version_id)
        df, integrity_ok = load_version_df(db, version)
        raw_ver = db.execute(select(DatasetVersion).where(DatasetVersion.dataset_id == ds.id, DatasetVersion.kind == "raw")
                             ).scalars().first()
        if raw_ver is not None:
            integrity_ok = integrity_ok and load_version_df(db, raw_ver)[1]
        provenance = 1.0 if (ds.source or "").strip() else 0.6
        if not integrity_ok:
            log_event(db, "integrity.hash_mismatch", resource_type="dataset", resource_id=ds.id, security=True)
            notify(db, "Integrity failure", f"SHA-256 mismatch for dataset '{ds.name}'", "critical")
            provenance = 0.0
        t0 = time.perf_counter()
        res, summary = det.run_detection(df, ds.label_column, provenance=provenance,
                                         integrity_failed=not integrity_ok, config=run.config)
        run.duration_s = time.perf_counter() - t0
        summary["integrity_verified"] = integrity_ok
        records = res.to_dict("records")
        for r in records:
            for k, v in list(r.items()):
                if isinstance(v, float) and np.isnan(v):
                    r[k] = None
        db.bulk_insert_mappings(DetectionResult, [{**r, "run_id": run.id} for r in records])
        q = 0
        for r in records:
            if r["category"] in QUARANTINE_CATEGORIES:
                db.add(QuarantinedRecord(dataset_id=ds.id, run_id=run.id, row_index=r["row_index"],
                                         trust_score=r["trust_score"], reasons=r["explanation"][:6]))
                q += 1
        summary["quarantined"] = q
        run.summary, run.status = summary, "completed"
        if q:
            ds.status = "awaiting_review"
        db.commit()
        if q:
            notify(db, "Records quarantined", f"{q} record(s) in '{ds.name}' need review.", "warning")
        log_event(db, "detection.completed", actor_id=run.created_by, resource_type="dataset", resource_id=ds.id,
                  detail={"quarantined": q})
    except Exception as e:
        db.rollback()
        run = db.get(DetectionRun, run_id)
        run.status, run.error = "failed", f"{type(e).__name__}: {e}"[:1000]
        db.commit()
        log.exception("detection failed")
    finally:
        db.close()


# ---------------- training ----------------
def run_training_job(run_id: str):
    db = SessionLocal()
    try:
        run = db.get(TrainingRun, run_id)
        ds = db.get(Dataset, run.dataset_id)
        run.status = "running"
        db.commit()
        version = db.get(DatasetVersion, run.version_id)
        df, ok = load_version_df(db, version)
        if not ok:
            raise RuntimeError("Dataset integrity verification failed (SHA-256 mismatch).")
        if run.target not in df.columns:
            raise ValueError("Target column not found")
        train, test = tr.split(df, run.target)
        pipe, metrics, secs = tr.train_and_eval(run.model_type, train, test, run.target)
        blob = tr.serialize(pipe)
        name = f"{ds.name}-{run.model_type}"
        ver = (db.execute(select(func.max(RegisteredModel.version)).where(RegisteredModel.name == name)).scalar() or 0) + 1
        key = f"models/{ds.id}/{run.id}.joblib"
        h = store_artifact(db, key, blob, "model")
        m = RegisteredModel(name=name, version=ver, model_type=run.model_type, dataset_id=ds.id, version_id=version.id,
                            training_run_id=run.id, artifact_key=key, sha256=h, metrics=metrics)
        db.add(m)
        db.flush()
        db.add(LineageEdge(dataset_id=ds.id, src_type="version", src_id=version.id, dst_type="model", dst_id=m.id,
                           operation=f"train:{run.model_type}"))
        run.metrics, run.train_time_s, run.status = metrics, secs, "completed"
        db.commit()
        notify(db, "Model trained", f"{name} v{ver}: accuracy {metrics['accuracy']:.3f}", "info")
        log_event(db, "model.trained", actor_id=run.created_by, resource_type="model", resource_id=m.id)
    except Exception as e:
        db.rollback()
        run = db.get(TrainingRun, run_id)
        run.status, run.error = "failed", f"{type(e).__name__}: {e}"[:1000]
        db.commit()
        log.exception("training failed")
    finally:
        db.close()


# ---------------- poisoning experiment ----------------
def _det_metrics(truth: np.ndarray, flagged: np.ndarray, score: np.ndarray) -> dict:
    from sklearn.metrics import roc_auc_score
    tp = int((truth & flagged).sum())
    fp = int((~truth & flagged).sum())
    fn = int((truth & ~flagged).sum())
    tn = int((~truth & ~flagged).sum())
    out = {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "accuracy": (tp + tn) / len(truth),
        "roc_auc": None,
    }
    out["f1"] = 2 * out["precision"] * out["recall"] / (out["precision"] + out["recall"]) if (out["precision"] + out["recall"]) else 0.0
    if truth.any() and (~truth).any():
        out["roc_auc"] = float(roc_auc_score(truth, score))
    return out


def run_experiment_job(exp_id: str, flag_below: float = 70.0):
    db = SessionLocal()
    try:
        exp = db.get(Experiment, exp_id)
        ds = db.get(Dataset, exp.dataset_id)
        exp.status = "running"
        db.commit()
        if not ds.label_column:
            raise ValueError("Dataset has no label column configured")
        version = latest_analysis_version(db, ds.id)
        df, ok = load_version_df(db, version)
        if not ok:
            raise RuntimeError("Dataset integrity verification failed (SHA-256 mismatch).")
        df, _ = pl.clean(df, ds.label_column)
        label = ds.label_column
        train_clean, test_clean = tr.split(df, label)   # untouched clean test set
        train_clean = train_clean.reset_index(drop=True)

        # 1. clean baseline
        _, m_clean, t_clean = tr.train_and_eval(exp.model_type, train_clean, test_clean, label)

        # 2. poison a COPY of the training split only
        poisoned, truth = po.poison(train_clean, label, exp.attack, exp.poison_rate, seed=42)
        key = f"experiments/{exp.id}/poisoned_train.csv"
        store_artifact(db, key, pl.to_csv_bytes(poisoned), "experiment_poisoned")
        gt_key = f"experiments/{exp.id}/ground_truth.npy"
        buf = io.BytesIO()
        np.save(buf, truth)
        store_artifact(db, gt_key, buf.getvalue(), "experiment_ground_truth")   # restricted metadata
        db.add(ExperimentGroundTruth(experiment_id=exp.id, artifact_key=gt_key, n_poisoned=int(truth.sum())))
        db.commit()
        _, m_pois, t_pois = tr.train_and_eval(exp.model_type, poisoned, test_clean, label)

        # 3. detection: receives ONLY the poisoned features/labels, never `truth`
        t0 = time.perf_counter()
        res, summary = det.run_detection(poisoned, label, provenance=None, config=None)
        det_time = time.perf_counter() - t0
        scores = res["trust_score"].fillna(0.0).values
        flagged = (scores < flag_below) | (res["category"] == "invalid").values

        # 4. evaluate detection against ground truth (after detection has finished)
        dm = _det_metrics(truth, flagged, 100.0 - scores)

        # 5. filtered model on same untouched test set
        kept = poisoned[~flagged].reset_index(drop=True)
        if kept[label].nunique() < 2 or len(kept) < 10:
            m_filt, t_filt = None, None
        else:
            _, m_filt, t_filt = tr.train_and_eval(exp.model_type, kept, test_clean, label)

        exp.results = {
            "clean": {**m_clean, "train_time_s": t_clean},
            "poisoned": {**m_pois, "train_time_s": t_pois},
            "filtered": None if m_filt is None else {**m_filt, "train_time_s": t_filt},
            "detection": {**dm, "flag_below": flag_below, "detection_time_s": det_time,
                          "retention": float(len(kept) / len(poisoned))},
            "n_train": int(len(poisoned)), "n_poisoned": int(truth.sum()), "n_flagged": int(flagged.sum()),
            "n_test": int(len(test_clean)),
            "note": "Detection never had access to ground-truth labels. Test set is clean and untouched.",
        }
        exp.status = "completed"
        db.commit()
        notify(db, "Experiment finished", f"{exp.name}: detection recall {dm['recall']:.2f}, precision {dm['precision']:.2f}")
        log_event(db, "experiment.completed", actor_id=exp.created_by, resource_type="experiment", resource_id=exp.id)
    except Exception as e:
        db.rollback()
        exp = db.get(Experiment, exp_id)
        exp.status, exp.error = "failed", f"{type(e).__name__}: {e}"[:1000]
        db.commit()
        log.exception("experiment failed")
    finally:
        db.close()


TASKS = {"pipeline": run_pipeline, "detection": run_detection_job, "training": run_training_job,
         "experiment": run_experiment_job}
