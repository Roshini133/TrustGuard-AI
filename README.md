# TrustGuard AI

**A Cloud-Native Intelligent Framework for Data Poisoning Detection, Trust Scoring, and Secure Machine Learning.**

React + TypeScript frontend · FastAPI backend · PostgreSQL · Redis/Celery · scikit-learn · Resend email · Docker · Render.

---

## 1. Verification status — read this first

Nothing below is claimed as working unless it was actually run. Honest status of this delivery:

| Area | Status | Evidence |
|---|---|---|
| Backend logic (auth, OTP, reset, datasets, pipeline, detection, trust score, quarantine, training, experiments, reports, RBAC, audit chain) | ✅ **Tested** | 47 pytest tests pass on **SQLite and real PostgreSQL 16** |
| Alembic migrations | ✅ **Tested** | `upgrade head`, `alembic check` (no drift) and `downgrade base → upgrade head` on real PostgreSQL 16 |
| Multi-process runtime (API + Celery worker + Redis + Postgres over real HTTP) | ✅ **Run once end-to-end** | register → OTP → login → upload → pipeline → detection → training → experiment → reports; Celery completed all jobs; Redis rate-limit keys created; 429 on brute force |
| Frontend (all 21 app pages + 7 public pages) | ✅ typecheck + production build; 23 Vitest tests (registration validation, OTP paste/cooldown/expiry, login, forgot/reset, redirects, protected routes, dashboard, API errors, CSRF, refresh) | |
| **Real email delivery via Resend** | ⛔ **NOT verified** | Needs your `RESEND_API_KEY` + permitted sender. Code path implemented; tests use a mock provider only. Follow [`docs/MANUAL_EMAIL_TEST.md`](docs/MANUAL_EMAIL_TEST.md). |
| **Docker images / `docker compose up`** | ⛔ **NOT built or run** | The build environment had no running Docker daemon. YAML/shell syntax was validated only. |
| **Render deployment** | ⛔ **NOT deployed** | No Render account access. `render.yaml` is syntax-checked only; follow §13. |
| Browser UI in a real browser (visual/layout, mobile) | ⛔ **Not visually inspected** | Component tests run in jsdom. Open the app and look before demoing. |
| Frontend tests against a real backend (Playwright/Cypress) | ❌ Not written | |

Known limitations are listed in §17.

---

## 2. Problem statement

Machine-learning systems trust their training data. An attacker (or a faulty pipeline) who can alter a small fraction of
records — flipping labels, nudging features, injecting rows, or planting backdoor triggers — can degrade or steer a model
without any code being compromised. TrustGuard AI gives data owners a workflow to **ingest data with provenance,
detect suspicious records, quantify trust, quarantine and review, and measure the real impact on model quality**.

## 3. Architecture

```mermaid
flowchart LR
  B[Browser<br/>React SPA] -->|HTTPS, same origin| N[nginx<br/>static + /api proxy]
  N -->|/api| A[FastAPI API]
  A --> P[(PostgreSQL<br/>users, OTP digests, runs,<br/>scores, audit, hashes)]
  A --> R[(Redis<br/>rate limits + job queue)]
  A --> O[(Object storage<br/>datasets, models)]
  A -->|enqueue| R
  R --> W[Celery worker + beat]
  W --> P
  W --> O
  A -->|HTTPS API| E[Resend<br/>transactional email]
```

**Data flow**

```mermaid
flowchart TD
  U[Upload CSV/XLSX] --> H[SHA-256 + store RAW artifact<br/>never overwritten]
  H --> V[Pipeline: schema validation,<br/>missing/duplicate/invalid analysis, cleaning]
  V --> C[New CLEANED version + lineage edge]
  C --> D[Detection: Isolation Forest, LOF,<br/>distribution + label consistency]
  D --> T[Data Trust Score per record + dataset]
  T --> Q{category}
  Q -->|highly suspicious / invalid| QU[Quarantine queue]
  QU --> RV[Review: approve / reject / investigate / release<br/>every action audited]
  RV --> F[FILTERED version]
  F --> M[Model training + registry<br/>hashes, versions]
  M --> I[Experiment lab: clean vs poisoned vs filtered<br/>on the same untouched clean test set]
```

### The four engineering modules
1. **Secure data engineering** — ingestion, validation, cleaning, versioning, lineage, SHA-256 provenance.
2. **AI detection & trust scoring** — Isolation Forest, LOF, robust distribution analysis, label consistency, trust formula.
3. **Secure ML & impact evaluation** — Logistic Regression / Random Forest / Decision Tree, registry, poisoning lab, impact comparison.
4. **Cloud-native security & operations** — email-verified auth, RBAC, tamper-evident audit log, Docker, Render, monitoring.

## 4. Technology stack
React 18, TypeScript, Vite, Tailwind CSS, React Router, TanStack Query, Recharts, Lucide icons ·
Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2, Alembic, PostgreSQL, Redis, Celery ·
pandas, NumPy, scikit-learn, joblib, ReportLab · Argon2id, PyJWT · Resend · Docker, nginx, Render.

## 5. Features
Everything in the spec is implemented in code; see §1 for what has been verified.
Dashboard (live stats + 6 charts) · dataset upload/versions/preview/download/hash verification/lineage · data-quality
reports · AI trust analysis with configurable weights/thresholds and per-record explanations · suspicious-record triage ·
quarantine with decision history and controlled release · model training & registry (hash-verified artifacts) ·
poisoning laboratory (label flip, feature manipulation, injection, backdoor-style) · model-impact comparison ·
security & integrity page · audit log (hash-chained, checkpointable) · CSV/PDF reports (9 types) · notification center ·
user/role management · system monitoring · settings · help.

## 6. Local installation without Docker (development)

```bash
# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example .env            # edit; for offline dev set EMAIL_PROVIDER=console (prints OTPs to the API log, dev only)
alembic upgrade head               # defaults to SQLite (./dev.db) unless DATABASE_URL is set
uvicorn app.main:app --reload      # http://localhost:8000/api/docs   (JOBS_MODE defaults to inline threads without Redis)

# Frontend (new terminal)
cd frontend && npm ci && npm run dev   # http://localhost:5173  (Vite proxies /api -> localhost:8000)
```
If you run the frontend on port 5173, set `FRONTEND_URL=http://localhost:5173` and `CORS_ORIGINS=http://localhost:5173`.

## 7. Environment configuration
All variables are in [`.env.example`](.env.example) with placeholders. Production (`APP_ENV=production`) **refuses to start**
if: secrets are missing/short/placeholder, `DATABASE_URL` is SQLite, `EMAIL_PROVIDER` ≠ `resend`, `RESEND_API_KEY` or
`EMAIL_FROM` is empty, `FRONTEND_URL` is not `https`, or `CORS_ORIGINS` contains `*`. Secrets are never passed to the
frontend build.

| Variable | Purpose |
|---|---|
| `APP_ENV`, `SERVICE_ROLE` | `production` enables strict validation; `worker` skips email/URL requirements |
| `APP_SECRET_KEY` | HMAC key for OTP / reset-token / refresh-token digests |
| `SESSION_SECRET` | signs short-lived access JWTs |
| `DATABASE_URL`, `REDIS_URL` | PostgreSQL (required in prod); Redis (rate limits + Celery) |
| `FRONTEND_URL`, `BACKEND_URL`, `CORS_ORIGINS` | public URLs; reset links are built **only** from `FRONTEND_URL` |
| `RESEND_API_KEY`, `EMAIL_FROM`, `EMAIL_PROVIDER` | email delivery |
| `OTP_EXPIRY_SECONDS` (300), `OTP_RESEND_COOLDOWN_SECONDS` (60), `OTP_MAX_ATTEMPTS` (5), `OTP_MAX_RESENDS` (5) | OTP policy |
| `PASSWORD_RESET_EXPIRY_SECONDS` (900) | reset-link lifetime |
| `ACCESS_TOKEN_EXPIRE_MINUTES` (15), `REFRESH_TOKEN_EXPIRE_DAYS` (7), `REMEMBER_ME_REFRESH_DAYS` (30) | sessions |
| `RATE_LIMIT_REGISTER/LOGIN/OTP_VERIFY/OTP_RESEND/FORGOT` | `max/windowSeconds` per IP and per account |
| `ARTIFACT_STORAGE_BACKEND`, `ARTIFACT_STORAGE_PATH`, `S3_*` | where datasets/models are stored |
| `FIRST_ADMIN_EMAIL` | address that becomes `admin` upon registration |
| `JOBS_MODE` | `celery`, `inline` (API threads) or `sync` |

## 8. Real email provider setup (Resend)
1. Create a Resend account → **API Keys** → create a key → `RESEND_API_KEY`.
2. **Sender requirement:** `EMAIL_FROM` must be permitted by Resend. For real users, add and verify a **domain**
   (Resend → Domains → add the SPF/DKIM DNS records) and use an address on it. Without a domain you can only use
   `onboarding@resend.dev`, which delivers **only to your own Resend account email** — fine for a first test, not for the public.
3. Set both variables (local `.env` or Render dashboard). They are read server-side only.
4. Delivery failures (bad key, unverified sender, rate limit, timeout) surface as HTTP `502` with a safe message; the
   account is **never** marked verified and the user can retry after the cooldown. The provider abstraction lives in
   `backend/app/email_service.py` (`EmailProvider`), so another provider is a single new class.
5. `EMAIL_PROVIDER=console` exists for offline development only and is **refused in production**.

## 9. Registration & OTP workflow
`POST /api/auth/register` validates input (email format, strength ≥10 chars w/ upper+lower+digit+symbol, confirmation,
terms), normalises the email (trim + lowercase), stores a **pending registration** (Argon2id hash — the password is never stored
in plaintext) and a challenge containing an **HMAC-SHA256 digest** of a 6-digit CSPRNG code (5-minute expiry, 5 attempts).
The code is emailed through Resend. The user is only created inside one transaction when `POST /api/auth/verify-email`
receives a matching, unexpired, unconsumed code (constant-time compare); the challenge and pending row are then deleted.
New challenges supersede old ones; resend has a 60 s cooldown and a cap; per-IP and per-account rate limits apply
(Redis-backed when configured). Pending rows, expired reset tokens and old sessions are purged by a Celery beat job every hour
and opportunistically on registration. OTPs are never logged, returned, or stored in browser storage (the browser keeps
only the email and timer hints in `sessionStorage`).

*Design note:* to prevent account enumeration, registering an **already-registered** email returns the same `202` response as a
fresh one and emails the existing owner a security notice instead.

## 10. Password-reset workflow
`POST /api/auth/forgot-password` always returns the same generic message. For a real verified account it creates a 32-byte
random token, stores only its HMAC digest (15-minute expiry, single use, older tokens invalidated) and emails a link
`FRONTEND_URL/reset-password#token=…` (fragment, so the token is not sent to servers/referrers; the page scrubs it from the address bar).
`POST /api/auth/reset-password` re-validates token + strength + confirmation, hashes with Argon2id, marks the token used and **revokes every session**
in one transaction, then sends a confirmation email. The user is **not** auto-logged-in.

## 11. Authentication & sessions
Short-lived access JWT (15 min) + rotating opaque refresh token, both in **HttpOnly** cookies (`Secure` in production,
`SameSite=Lax`); refresh tokens and CSRF secrets are stored only as digests server-side. A readable `tg_csrf` cookie is
echoed in `X-CSRF-Token` (double-submit, also checked against the session digest) on every state-changing request.
Logout/password-reset/disable revoke sessions. The backend enforces authorization on every endpoint; frontend route guards are UX only.
Roles: `viewer`, `analyst`, `reviewer`, `admin` (see Admin → User management for the permission matrix).

The frontend nginx **proxies `/api` to the backend**, so the browser sees a single origin: first-party cookies, no wildcard/credentialed CORS needed.

## 12. Local Docker setup
```bash
cp .env.example .env     # set RESEND_API_KEY / EMAIL_FROM for real email, or EMAIL_PROVIDER=console for offline dev
docker compose up --build -d          # start (db, redis, api[runs migrations], worker+beat, web)
open http://localhost:8080            # app      | http://localhost:8000/api/docs  API docs
docker compose ps                     # status / health
docker compose logs -f api worker     # inspect
docker compose exec api alembic current
docker compose down                   # stop (keeps volumes)   |  docker compose down -v   # also wipe data
docker compose up --build -d api web  # rebuild after code changes
```
Persistent named volumes: `pgdata` (PostgreSQL), `redisdata`, `artifacts` (shared by API + worker).
**Not executed in the authoring environment** — if the build fails, please report the error.

## 13. Render deployment
Architecture in `render.yaml`: `trustguard-web` (nginx, Docker) → private network → `trustguard-api` (Docker, runs migrations) ·
`trustguard-worker` (Docker, Celery + beat) · `trustguard-db` (managed Postgres) · `trustguard-redis` (Key Value) ·
**S3-compatible object storage** (e.g., Cloudflare R2, Backblaze B2, AWS S3) · Resend.

Why object storage and not a Render disk: a Render persistent disk attaches to a single service, but the API (uploads) and the
worker (processing) must read the same files, and the container filesystem is ephemeral. (If you prefer a single service:
set `JOBS_MODE=inline`, drop the worker, and attach one disk to the API with `ARTIFACT_STORAGE_BACKEND=local`.)

Steps:
1. Push this repo to GitHub. Create an S3-compatible bucket and an access key.
2. Render → **New → Blueprint** → select the repo. Fill in the prompted secrets: `RESEND_API_KEY`, `EMAIL_FROM`, `S3_*`, `FIRST_ADMIN_EMAIL`
   (and enter the same `S3_*` values for the worker). `APP_SECRET_KEY`/`SESSION_SECRET` are generated.
3. After the first deploy note the public URL of **trustguard-web** (e.g. `https://trustguard-web-xxxx.onrender.com`). Set on `trustguard-api`:
   `FRONTEND_URL` = that URL, `CORS_ORIGINS` = that URL, `BACKEND_URL` = the API's URL; redeploy the API.
   The API validates config at startup and **will not boot** in production if anything is unsafe — check its logs.
4. Health checks: web `/healthz`, API `/health/ready` (DB reachable). Migrations run automatically on API start.
5. Run the verification list in §14, then [`docs/MANUAL_EMAIL_TEST.md`](docs/MANUAL_EMAIL_TEST.md).

Cost/persistence notes: the Postgres `free` plan **expires** — switch `plan:` to a paid plan for lasting data. Workers have no free plan.
Free web services spin down when idle (cold starts).

## 14. Post-deployment verification checklist (do not skip)
Frontend loads · `GET /health/ready` = 200 · register → real OTP arrives → verify → login · forgot-password email arrives and the
link opens your **deployed** frontend · reset works, old sessions die · unauthenticated `GET /api/datasets` = 401 · upload a file,
restart the API service from the dashboard, file still downloads with the same SHA-256 · run pipeline/analysis/experiment (worker completes them) ·
download a PDF report · Admin → System shows DB/Redis/storage healthy.

## 15. Database migrations
Alembic lives in `backend/alembic`. `alembic upgrade head` (the API container does this on start; only the API service, via `RUN_MIGRATIONS`).
Create a new one: `alembic revision --autogenerate -m "msg"` → review → commit. CI runs `alembic upgrade head && alembic check` against PostgreSQL.

## 16. Using the platform
**Sample data:** *Datasets → Generate sample*, or `python scripts/generate_sample_dataset.py 1000 sample.csv`.
**AI analysis:** Data engineering → run pipeline; AI trust analysis → run. *Trust = 100·(0.25·StatisticalNormality + 0.25·LabelConsistency +
0.20·Provenance + 0.15·DataQuality + 0.15·ModelImpactSafety)*, components in 0–1, weights/thresholds configurable
(≥80 High Trust, 50–79 Requires Review, <50 Highly Suspicious). Unavailable evidence gets a neutral 0.5 (never 1.0) and is listed in the result; if
available weight < 0.5 the class is `insufficient_evidence`; unusable rows are `invalid`; a failed SHA-256 check forces `highly_suspicious` regardless of score.
Statistical normality combines Isolation Forest, LOF and robust-z distribution analysis; label consistency combines k-NN agreement and out-of-fold Random-Forest probability;
model-impact safety is a gradient-norm influence proxy that penalises the top decile.
**Poisoning experiments:** Experiment lab → choose attack/rate/model. The experiment poisons a *copy of the training split only*, records ground truth in a
restricted table (admin-only summary; detection function has no parameter for it — asserted by a test), runs detection blind, scores detection against ground truth afterwards,
and trains clean / poisoned / filtered models evaluated on the same untouched clean test set. All reported numbers come from real runs.
**Model evaluation:** reproducible (seed 42, stratified 80/20), metrics: accuracy, precision, recall, F1, ROC-AUC.

## 17. Limitations (be upfront in your report)
- **Backdoor-style poisoning is poorly detected** by these unsupervised/statistical signals (ROC-AUC ≈ 0.77, precision < 0.2 in our synthetic probe). Label-flip, feature-manipulation and injection are detected well (ROC-AUC 0.96–0.98; ~0.7–0.8 precision at ~0.85 recall with the default threshold of 70).
  These figures come from one synthetic dataset and are **not** a general guarantee.
- Anomalies are evidence, not proof; thresholds need tuning per dataset. Label-dependent evidence needs a label column and ≥2 classes with ≥2 members each.
- Detection runs in memory: designed for tens of thousands of rows, not millions. PDF reports show at most 1,500 rows (CSV is complete up to 50,000 trust/anomaly rows and 5,000 audit events).
- Tabular classification only. Experiments clean (dedupe/impute) before splitting.
- Notifications addressed to "everyone" share one read flag across users.
- Provenance reliability is a simple rule (declared source + verified hash); there is no external attestation.
- The audit chain is tamper-*evident* against edits; an attacker with full DB write access could rebuild it. Use `Create audit checkpoint` and store the hash externally.
- No SSO/2FA beyond email verification. Email delivery depends on Resend and your domain setup.
- Not yet exercised: Docker image builds, Render deployment, real Resend delivery, real-browser/mobile visual QA, load testing.

## 18. Testing
```bash
cd backend && pip install -r requirements.txt && pytest -q                       # SQLite (47 tests)
TEST_DATABASE_URL=postgresql://user:pass@localhost:5432/trustguard_test pytest -q # PostgreSQL
cd frontend && npm ci && npm test && npm run typecheck && npm run build         # 23 tests
```
Backend tests cover: registration, duplicate handling, OTP correct/incorrect/expired/replay/attempt-limit/cooldown/supersede, email-failure handling, rate limiting,
login/logout/CSRF/refresh rotation, forgot/reset (valid/expired/replay/session revocation), production config validation, upload validation, XLSX, SHA-256 + tamper detection,
pipeline & lineage, trust-score formula & missing evidence & integrity-failure override, detection → quarantine → review/release flow, training (3 algorithms) & registry, all four poisoning functions,
end-to-end experiments, ground-truth isolation, RBAC & resource-level authorization, audit-chain tamper detection, CSV/PDF reports + CSV formula-injection defence, dashboard, notifications.

## 19. Security considerations
Argon2id password hashing · HMAC-digested OTPs/reset/refresh tokens · constant-time comparison · HttpOnly/Secure/SameSite cookies + CSRF double-submit ·
rate limits (IP + account) · generic responses against enumeration · server-side RBAC and per-resource authorization (404 for foreign resources) ·
upload validation (extension, magic bytes, size, schema) · artifact keys never exposed as paths · SHA-256 verification before processing and download ·
hash-chained audit log without secrets · security headers + CSP (nginx) · no secrets in the frontend bundle · production startup validation · CSV formula-injection neutralisation in exports.

## 20. Troubleshooting
| Symptom | Likely cause / fix |
|---|---|
| API exits: "Invalid production configuration" | read the listed items; set secrets (≥32 chars), https `FRONTEND_URL`, Resend vars |
| Registration returns 502 | Resend rejected the send: wrong key, unverified sender/domain, or recipient not allowed by `onboarding@resend.dev`. See `auth.otp_email_failed` in Audit logs |
| No email arrives but 202 | check spam; Resend dashboard → Emails; confirm `EMAIL_FROM` domain is verified |
| Login works but pages 401 | cookies blocked / `FRONTEND_URL` scheme mismatch; in production cookies are `Secure` (https only) |
| Reset link goes to localhost | `FRONTEND_URL` not set on the API service |
| Jobs stay "queued" | worker not running or `REDIS_URL` wrong; Admin → System → Background jobs shows mode |
| `403 CSRF validation failed` | stale tab after logout/login; reload. Non-browser clients must send `X-CSRF-Token` equal to the `tg_csrf` cookie |
| Upload lost after redeploy | you used `local` storage on ephemeral disk; use `s3` |
