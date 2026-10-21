"""Job dispatch. JOBS_MODE: celery (Redis broker) | inline (thread pool in API process) | sync (tests)."""
import logging
import os
from concurrent.futures import ThreadPoolExecutor

from .config import get_settings
from .tasks import TASKS

log = logging.getLogger("trustguard.jobs")
_pool = ThreadPoolExecutor(max_workers=2)


def mode() -> str:
    m = os.environ.get("JOBS_MODE", "").lower()
    if m in ("celery", "inline", "sync"):
        return m
    return "celery" if get_settings().REDIS_URL else "inline"


def enqueue(kind: str, entity_id: str):
    m = mode()
    fn = TASKS[kind]
    if m == "sync":
        fn(entity_id)
    elif m == "inline":
        _pool.submit(fn, entity_id)
    else:
        from .celery_app import celery
        celery.send_task(f"trustguard.{kind}", args=[entity_id])
    log.info("enqueued %s (%s)", kind, m)
