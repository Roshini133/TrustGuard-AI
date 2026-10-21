from celery import Celery

from .config import get_settings
from .tasks import TASKS

s = get_settings()
celery = Celery("trustguard", broker=s.REDIS_URL or "memory://", backend=s.REDIS_URL or None)
celery.conf.update(task_serializer="json", accept_content=["json"], task_acks_late=True,
                   worker_prefetch_multiplier=1, task_time_limit=3600, broker_connection_retry_on_startup=True,
                   timezone="UTC",
                   beat_schedule={"cleanup-expired": {"task": "trustguard.cleanup", "schedule": 3600.0}})

for _name, _fn in TASKS.items():
    celery.task(name=f"trustguard.{_name}")(_fn)


@celery.task(name="trustguard.cleanup")
def cleanup():
    """Scheduled cleanup of expired pending registrations, reset tokens and sessions."""
    from .db import SessionLocal
    from .routers.auth import _cleanup_expired
    db = SessionLocal()
    try:
        _cleanup_expired(db)
    finally:
        db.close()
