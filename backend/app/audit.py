"""Tamper-evident audit log: each event stores SHA-256 over (prev_hash + canonical payload)."""
import hashlib
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AuditEvent, AuditCheckpoint, Notification


def _ts(dt) -> str:
    """Canonical UTC timestamp string, identical whether the DB returns aware or naive datetimes."""
    from datetime import timezone
    if dt is None:
        return ""
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.replace(microsecond=0).isoformat()


def _payload(e: AuditEvent) -> str:
    return json.dumps({
        "ts": _ts(e.ts), "actor": e.actor_id, "action": e.action,
        "rt": e.resource_type, "rid": e.resource_id, "detail": e.detail, "sec": e.is_security, "ip": e.ip,
    }, sort_keys=True, default=str)


def _calc(prev: str, e: AuditEvent) -> str:
    return hashlib.sha256((prev + _payload(e)).encode()).hexdigest()


def log_event(db: Session, action: str, actor_id: str | None = None, resource_type: str = "",
              resource_id: str = "", detail: dict | None = None, security: bool = False, ip: str = "",
              commit: bool = True) -> AuditEvent:
    """Never pass secrets in `detail`."""
    from datetime import datetime, timezone
    last = db.execute(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1)).scalar_one_or_none()
    e = AuditEvent(ts=datetime.now(timezone.utc).replace(microsecond=0), actor_id=actor_id, action=action,
                   resource_type=resource_type, resource_id=resource_id, detail=detail or {},
                   is_security=security, ip=ip, prev_hash=last.hash if last else "")
    e.hash = _calc(e.prev_hash, e)
    db.add(e)
    if commit:
        db.commit()
    else:
        db.flush()
    return e


def verify_chain(db: Session) -> dict:
    prev = ""
    n = 0
    for e in db.execute(select(AuditEvent).order_by(AuditEvent.id)).scalars():
        # ts may lose tzinfo on some backends; compare using stored hash recomputation with normalized iso
        if e.prev_hash != prev or _calc(prev, e) != e.hash:
            return {"valid": False, "broken_at": e.id, "checked": n}
        prev = e.hash
        n += 1
    return {"valid": True, "checked": n}


def checkpoint(db: Session) -> AuditCheckpoint | None:
    last = db.execute(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1)).scalar_one_or_none()
    if not last:
        return None
    cp = AuditCheckpoint(last_event_id=last.id, hash=last.hash)
    db.add(cp)
    db.commit()
    return cp


def notify(db: Session, title: str, body: str = "", level: str = "info", user_id: str | None = None, commit=True):
    db.add(Notification(title=title, body=body, level=level, user_id=user_id))
    if commit:
        db.commit()
