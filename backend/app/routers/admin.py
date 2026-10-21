"""Dashboard, notifications, audit, integrity, administration, health."""
import os
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select, text, update
from sqlalchemy.orm import Session

from .. import jobs
from ..audit import checkpoint, log_event, verify_chain
from ..config import get_settings
from ..db import get_db
from ..deps import ROLE_PERMS, current_user, require, require_admin
from ..models import (AppSetting, AuditEvent, Dataset, DatasetVersion, DetectionResult, DetectionRun, Experiment,
                      Notification, PipelineRun, QuarantinedRecord, RegisteredModel, TrainingRun, User, UserSession)
from ..storage import get_storage
from ..security import sha256_bytes

router = APIRouter(prefix="/api", tags=["admin"])
GLOBAL = ("admin", "reviewer", "viewer")


def _owned(user: User):
    return None if user.role in GLOBAL else select(Dataset.id).where(Dataset.owner_id == user.id)


# ---------------- dashboard ----------------
@router.get("/dashboard")
def dashboard(user: User = Depends(require("dataset:read")), db: Session = Depends(get_db)):
    owned = _owned(user)

    def scope(q, col):
        return q if owned is None else q.where(col.in_(owned))

    n_ds = db.execute(scope(select(func.count(Dataset.id)), Dataset.id)).scalar()
    status_counts = dict(db.execute(scope(select(Dataset.status, func.count()).group_by(Dataset.status), Dataset.id)).all())
    # latest completed detection per dataset
    latest = {}
    for r in db.execute(scope(select(DetectionRun).where(DetectionRun.status == "completed").order_by(DetectionRun.created_at), DetectionRun.dataset_id)).scalars():
        latest[r.dataset_id] = r
    cat, flags, hist, processed, suspicious = {}, {"isolation_forest": 0, "local_outlier_factor": 0, "feature_distribution": 0, "label_consistency": 0}, [0] * 10, 0, 0
    for r in latest.values():
        sm = r.summary or {}
        processed += sm.get("n_records", 0)
        for k, v in (sm.get("category_counts") or {}).items():
            cat[k] = cat.get(k, 0) + v
        for k, v in (sm.get("method_flags") or {}).items():
            flags[k] = flags.get(k, 0) + (v or 0)
    if latest:
        for s in db.execute(select(DetectionResult.trust_score).where(DetectionResult.run_id.in_([r.id for r in latest.values()]))).scalars():
            if s is not None:
                hist[min(9, int(s // 10))] += 1
    suspicious = cat.get("highly_suspicious", 0) + cat.get("invalid", 0)
    trusted = cat.get("high_trust", 0)
    in_q = db.execute(scope(select(func.count(QuarantinedRecord.id)).where(QuarantinedRecord.status.in_(("quarantined", "investigating"))), QuarantinedRecord.dataset_id)).scalar()
    issues = db.execute(scope(select(PipelineRun).where(PipelineRun.status == "completed").order_by(PipelineRun.finished_at), PipelineRun.dataset_id)).scalars().all()
    issues_total = sum(r.report["quality"]["issue_count"] for r in issues)
    issue_series = [{"date": r.finished_at.strftime("%Y-%m-%d"), "issues": r.report["quality"]["issue_count"]} for r in issues if r.finished_at][-20:]
    n_models = db.execute(scope(select(func.count(RegisteredModel.id)), RegisteredModel.dataset_id)).scalar()
    active_exp = db.execute(scope(select(func.count(Experiment.id)).where(Experiment.status.in_(("queued", "running"))), Experiment.dataset_id)).scalar()
    exps = db.execute(scope(select(Experiment).where(Experiment.status == "completed").order_by(Experiment.created_at.desc()).limit(10), Experiment.dataset_id)).scalars().all()
    exp_all = db.execute(scope(select(Experiment.status, func.count()).group_by(Experiment.status), Experiment.dataset_id)).all()
    notes = db.execute(select(Notification).where(or_(Notification.user_id == user.id, Notification.user_id.is_(None)))
                       .order_by(Notification.created_at.desc()).limit(5)).scalars().all()
    sec = []
    if user.role in ("admin", "reviewer"):
        sec = db.execute(select(AuditEvent).where(AuditEvent.is_security == True).order_by(AuditEvent.id.desc()).limit(5)).scalars().all()  # noqa: E712
    return {
        "stats": {"total_datasets": n_ds, "records_processed": processed, "suspicious_records": suspicious,
                  "quarantined_records": in_q, "awaiting_review": status_counts.get("awaiting_review", 0),
                  "data_quality_issues": issues_total, "models_trained": n_models, "active_experiments": active_exp},
        "charts": {
            "trust_distribution": [{"range": f"{i*10}-{i*10+10}", "count": c} for i, c in enumerate(hist)],
            "trusted_vs_suspicious": [{"name": "High trust", "value": trusted}, {"name": "Requires review", "value": cat.get("requires_review", 0)},
                                      {"name": "Suspicious", "value": suspicious}, {"name": "Insufficient evidence", "value": cat.get("insufficient_evidence", 0)}],
            "detection_methods": [{"method": k.replace("_", " ").title(), "flagged": v} for k, v in flags.items()],
            "model_before_after": [{"experiment": e.name[:24], "clean": e.results["clean"]["accuracy"], "poisoned": e.results["poisoned"]["accuracy"],
                                    "filtered": (e.results.get("filtered") or {}).get("accuracy")} for e in reversed(exps)],
            "experiment_outcomes": [{"status": s, "count": c} for s, c in exp_all],
            "quality_issues_over_time": issue_series,
        },
        "recent_alerts": [{"id": n.id, "title": n.title, "body": n.body, "level": n.level, "created_at": n.created_at} for n in notes],
        "recent_security_events": [{"id": e.id, "action": e.action, "ts": e.ts, "ip": e.ip} for e in sec],
    }


# ---------------- notifications ----------------
def _n_out(n):
    return {"id": n.id, "title": n.title, "body": n.body, "level": n.level, "read": n.read, "created_at": n.created_at}


@router.get("/notifications")
def notifications(unread_only: bool = False, user: User = Depends(current_user), db: Session = Depends(get_db)):
    q = select(Notification).where(or_(Notification.user_id == user.id, Notification.user_id.is_(None)))
    if unread_only:
        q = q.where(Notification.read == False)  # noqa: E712
    rows = db.execute(q.order_by(Notification.created_at.desc()).limit(100)).scalars().all()
    unread = db.execute(select(func.count(Notification.id)).where(or_(Notification.user_id == user.id, Notification.user_id.is_(None)),
                                                                  Notification.read == False)).scalar()  # noqa: E712
    return {"items": [_n_out(n) for n in rows], "unread": unread}


@router.post("/notifications/{nid}/read")
def mark_read(nid: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    n = db.get(Notification, nid)
    if not n or (n.user_id and n.user_id != user.id):
        raise HTTPException(404, "Not found")
    n.read = True
    db.commit()
    return _n_out(n)


@router.post("/notifications/read-all")
def mark_all(user: User = Depends(current_user), db: Session = Depends(get_db)):
    db.execute(update(Notification).where(or_(Notification.user_id == user.id, Notification.user_id.is_(None))).values(read=True))
    db.commit()
    return {"ok": True}


# ---------------- audit & integrity ----------------
@router.get("/audit")
def audit(action: str = "", security: bool | None = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
          user: User = Depends(require_admin), db: Session = Depends(get_db)):
    q = select(AuditEvent)
    if action:
        q = q.where(AuditEvent.action.ilike(f"%{action}%"))
    if security is not None:
        q = q.where(AuditEvent.is_security == security)
    total = db.execute(select(func.count()).select_from(q.subquery())).scalar()
    rows = db.execute(q.order_by(AuditEvent.id.desc()).offset((page - 1) * page_size).limit(page_size)).scalars().all()
    return {"items": [{"id": e.id, "ts": e.ts, "actor_id": e.actor_id, "action": e.action, "resource_type": e.resource_type,
                       "resource_id": e.resource_id, "detail": e.detail, "is_security": e.is_security, "ip": e.ip, "hash": e.hash}
                      for e in rows], "total": total, "page": page, "page_size": page_size}


@router.get("/integrity/overview")
def integrity_overview(user: User = Depends(require("dataset:read")), db: Session = Depends(get_db)):
    owned = _owned(user)
    q = select(DatasetVersion, Dataset.name).join(Dataset, Dataset.id == DatasetVersion.dataset_id)
    if owned is not None:
        q = q.where(DatasetVersion.dataset_id.in_(owned))
    items = []
    for v, name in db.execute(q.order_by(DatasetVersion.created_at.desc()).limit(200)).all():
        try:
            ok = sha256_bytes(get_storage().get(v.artifact_key)) == v.sha256
        except Exception:
            ok = False
        items.append({"dataset": name, "version": v.version, "kind": v.kind, "sha256": v.sha256, "verified": ok})
    models = []
    mq = select(RegisteredModel)
    if owned is not None:
        mq = mq.where(RegisteredModel.dataset_id.in_(owned))
    for m in db.execute(mq.limit(100)).scalars():
        try:
            ok = sha256_bytes(get_storage().get(m.artifact_key)) == m.sha256
        except Exception:
            ok = False
        models.append({"model": f"{m.name} v{m.version}", "sha256": m.sha256, "verified": ok})
    sec_events = db.execute(select(func.count(AuditEvent.id)).where(AuditEvent.is_security == True)).scalar() if user.role in ("admin", "reviewer") else None  # noqa: E712
    return {"datasets": items, "models": models, "security_event_count": sec_events,
            "audit_chain": verify_chain(db) if user.role == "admin" else None}


@router.post("/integrity/audit-checkpoint")
def audit_checkpoint(user: User = Depends(require_admin), db: Session = Depends(get_db)):
    cp = checkpoint(db)
    if not cp:
        raise HTTPException(409, "No audit events yet")
    log_event(db, "audit.checkpoint", actor_id=user.id)
    return {"id": cp.id, "last_event_id": cp.last_event_id, "hash": cp.hash}


# ---------------- admin: users / roles / settings ----------------
@router.get("/admin/users")
def users(search: str = "", user: User = Depends(require_admin), db: Session = Depends(get_db)):
    q = select(User)
    if search:
        q = q.where(or_(User.email.ilike(f"%{search}%"), User.full_name.ilike(f"%{search}%")))
    return {"items": [{"id": u.id, "email": u.email, "full_name": u.full_name, "role": u.role, "is_active": u.is_active,
                       "is_verified": u.is_verified, "created_at": u.created_at, "last_login_at": u.last_login_at}
                      for u in db.execute(q.order_by(User.created_at.desc()).limit(200)).scalars()]}


class UserPatch(BaseModel):
    role: str | None = Field(None, pattern="^(admin|analyst|reviewer|viewer)$")
    is_active: bool | None = None


@router.patch("/admin/users/{uid}")
def patch_user(uid: str, body: UserPatch, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    u = db.get(User, uid)
    if not u:
        raise HTTPException(404, "User not found")
    if u.id == admin.id and (body.role not in (None, "admin") or body.is_active is False):
        raise HTTPException(409, "You cannot demote or disable your own account.")
    changes = {}
    if body.role is not None and body.role != u.role:
        changes["role"] = [u.role, body.role]
        u.role = body.role
    if body.is_active is not None and body.is_active != u.is_active:
        changes["is_active"] = [u.is_active, body.is_active]
        u.is_active = body.is_active
        if not body.is_active:
            db.execute(update(UserSession).where(UserSession.user_id == u.id).values(revoked=True))
    if changes:
        db.commit()
        log_event(db, "admin.user_updated", actor_id=admin.id, resource_type="user", resource_id=u.id, detail=changes, security=True)
    return {"id": u.id, "role": u.role, "is_active": u.is_active}


@router.get("/admin/roles")
def roles(user: User = Depends(require_admin)):
    return {"items": [{"role": r, "permissions": sorted(p)} for r, p in ROLE_PERMS.items()]}


@router.get("/admin/settings")
def get_settings_api(user: User = Depends(require_admin), db: Session = Depends(get_db)):
    from ..ml.detection import DEFAULT_CONFIG
    row = db.get(AppSetting, "detection_defaults")
    return {"detection_defaults": row.value if row else DEFAULT_CONFIG}


class SettingsIn(BaseModel):
    detection_defaults: dict


@router.put("/admin/settings")
def put_settings(body: SettingsIn, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    from ..ml.detection import merged_config
    try:
        cfg = merged_config(body.detection_defaults)
    except ValueError as e:
        raise HTTPException(422, str(e))
    row = db.get(AppSetting, "detection_defaults")
    if row:
        row.value = cfg
        row.updated_at = datetime.now(timezone.utc)
    else:
        db.add(AppSetting(key="detection_defaults", value=cfg))
    db.commit()
    log_event(db, "admin.settings_updated", actor_id=user.id, resource_type="settings", resource_id="detection_defaults")
    return {"detection_defaults": cfg}


# ---------------- admin: monitoring ----------------
@router.get("/admin/jobs")
def job_monitor(user: User = Depends(require_admin), db: Session = Depends(get_db)):
    out = []
    for kind, M in (("pipeline", PipelineRun), ("detection", DetectionRun), ("training", TrainingRun), ("experiment", Experiment)):
        for r in db.execute(select(M).order_by(M.created_at.desc()).limit(15)).scalars():
            out.append({"kind": kind, "id": r.id, "status": r.status, "created_at": r.created_at, "error": getattr(r, "error", "")})
    out.sort(key=lambda x: x["created_at"], reverse=True)
    counts = {}
    for it in out:
        counts[it["status"]] = counts.get(it["status"], 0) + 1
    return {"mode": jobs.mode(), "counts": counts, "items": out[:50]}


@router.get("/admin/errors")
def errors(user: User = Depends(require_admin), db: Session = Depends(get_db)):
    items = []
    for kind, M in (("pipeline", PipelineRun), ("detection", DetectionRun), ("training", TrainingRun), ("experiment", Experiment)):
        for r in db.execute(select(M).where(M.status == "failed").order_by(M.created_at.desc()).limit(20)).scalars():
            items.append({"kind": kind, "id": r.id, "error": r.error, "created_at": r.created_at})
    items.sort(key=lambda x: x["created_at"], reverse=True)
    return {"items": items[:50]}


def health_checks(db: Session) -> dict:
    s = get_settings()
    out = {}
    try:
        db.execute(text("select 1"))
        out["database"] = {"ok": True}
    except Exception as e:
        out["database"] = {"ok": False, "error": type(e).__name__}
    if s.REDIS_URL:
        try:
            import redis
            redis.Redis.from_url(s.REDIS_URL, socket_timeout=2).ping()
            out["redis"] = {"ok": True}
        except Exception as e:
            out["redis"] = {"ok": False, "error": type(e).__name__}
    else:
        out["redis"] = {"ok": None, "note": "not configured (in-memory rate limiting; inline jobs)"}
    try:
        key = "healthcheck/probe.txt"
        get_storage().put(key, b"ok")
        out["storage"] = {"ok": get_storage().get(key) == b"ok", "backend": s.ARTIFACT_STORAGE_BACKEND}
    except Exception as e:
        out["storage"] = {"ok": False, "error": type(e).__name__}
    out["email"] = {"ok": bool(s.RESEND_API_KEY and s.EMAIL_FROM) if s.EMAIL_PROVIDER == "resend" else None,
                    "provider": s.EMAIL_PROVIDER, "note": "configuration presence only; delivery must be tested manually"}
    return out


@router.get("/admin/health")
def admin_health(user: User = Depends(require_admin), db: Session = Depends(get_db)):
    return {"env": get_settings().APP_ENV, "jobs_mode": jobs.mode(), "checks": health_checks(db)}
