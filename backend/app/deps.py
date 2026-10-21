from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .db import get_db
from .models import User, UserSession
from .security import decode_access_token, digests_equal, hmac_digest

ACCESS_COOKIE = "tg_access"
REFRESH_COOKIE = "tg_refresh"
CSRF_COOKIE = "tg_csrf"
SAFE = {"GET", "HEAD", "OPTIONS"}

ROLE_PERMS = {
    "viewer": {"dataset:read", "report:read", "notification:read"},
    "analyst": {"dataset:read", "dataset:write", "pipeline:run", "detect:run", "model:train", "experiment:run",
                "quarantine:review", "report:read", "notification:read"},
    "reviewer": {"dataset:read", "quarantine:review", "quarantine:release", "report:read", "notification:read"},
    "admin": {"*"},
}


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def check_csrf(request: Request, session: UserSession):
    if request.method in SAFE:
        return
    header = request.headers.get("x-csrf-token", "")
    cookie = request.cookies.get(CSRF_COOKIE, "")
    if not header or not cookie or not digests_equal(header, cookie) \
            or not digests_equal(hmac_digest(header, "csrf"), session.csrf_digest):
        raise HTTPException(403, "CSRF validation failed")


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get(ACCESS_COOKIE)
    auth = request.headers.get("authorization", "")
    if not token and auth.lower().startswith("bearer "):
        token = auth[7:]
    claims = decode_access_token(token) if token else None
    if not claims:
        raise HTTPException(401, "Not authenticated")
    sess = db.get(UserSession, claims["sid"])
    if not sess or sess.revoked or _aware(sess.expires_at) < datetime.now(timezone.utc):
        raise HTTPException(401, "Session expired")
    if ACCESS_COOKIE in request.cookies:
        check_csrf(request, sess)
    user = db.get(User, claims["sub"])
    if not user or not user.is_active or not user.is_verified:
        raise HTTPException(401, "Account not available")
    request.state.session_id = sess.id
    return user


def has_perm(user: User, perm: str) -> bool:
    perms = ROLE_PERMS.get(user.role, set())
    return "*" in perms or perm in perms


def require(perm: str):
    def dep(user: User = Depends(current_user)) -> User:
        if not has_perm(user, perm):
            raise HTTPException(403, "Insufficient permissions")
        return user
    return dep


def require_admin(user: User = Depends(current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(403, "Administrator access required")
    return user
