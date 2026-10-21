import logging
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from .config import get_settings
from .db import SessionLocal, engine
from .routers import admin, analysis, auth, datasets, reports

settings = get_settings()  # validates configuration; raises on invalid production config

logging.basicConfig(level=logging.INFO, format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}')
log = logging.getLogger("trustguard")

app = FastAPI(title="TrustGuard AI API", version="1.0.0", docs_url="/api/docs", openapi_url="/api/openapi.json",
              redoc_url=None)

app.add_middleware(CORSMiddleware, allow_origins=settings.cors_list, allow_credentials=True,
                   allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"], allow_headers=["Content-Type", "X-CSRF-Token", "Authorization"])


@app.middleware("http")
async def security_headers(request: Request, call_next):
    rid = str(uuid.uuid4())[:8]
    t0 = time.perf_counter()
    try:
        resp = await call_next(request)
    except Exception:
        log.exception("unhandled error rid=%s path=%s", rid, request.url.path)
        return JSONResponse({"detail": "Internal server error", "request_id": rid}, status_code=500)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Request-ID"] = rid
    if request.url.path.startswith("/api/auth"):
        resp.headers["Cache-Control"] = "no-store"
    if settings.is_prod:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    log.info("%s %s %s %.0fms", request.method, request.url.path, resp.status_code, (time.perf_counter() - t0) * 1000)
    return resp


for r in (auth.router, datasets.router, analysis.router, reports.router, admin.router):
    app.include_router(r)


@app.get("/health", tags=["health"])
def health():
    return {"status": "ok"}


@app.get("/health/ready", tags=["health"])
def ready():
    try:
        with engine.connect() as c:
            c.execute(text("select 1"))
        return {"status": "ready"}
    except Exception:
        return JSONResponse({"status": "unavailable"}, status_code=503)
