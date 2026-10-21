import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import email_service as es
from ..audit import log_event, notify
from ..config import get_settings
from ..db import get_db
from ..deps import ACCESS_COOKIE, CSRF_COOKIE, REFRESH_COOKIE, ROLE_PERMS, _aware, check_csrf, current_user
from ..models import (EmailVerificationChallenge, PasswordResetToken, PendingRegistration, User, UserSession)
from ..ratelimit import client_ip, enforce
from ..security import (create_access_token, digests_equal, generate_otp, hash_password, hmac_digest,
                        normalize_email, password_problems, random_token, verify_password)

router = APIRouter(prefix="/api/auth", tags=["auth"])
log = logging.getLogger("trustguard.auth")

_DUMMY_HASH = hash_password("dummy-password-for-timing")
GENERIC_REGISTER = "If the address can be registered, a verification code has been sent."
GENERIC_FORGOT = "If an account exists for that email, a password reset link has been sent."


def utcnow():
    return datetime.now(timezone.utc)


def mask_email(e: str) -> str:
    local, _, dom = e.partition("@")
    return (local[:2] + "***" if len(local) > 2 else local[:1] + "***") + "@" + dom


def _check_pw(pw: str):
    probs = password_problems(pw)
    if probs:
        raise HTTPException(422, "Password must contain " + ", ".join(probs) + ".")


class RegisterIn(BaseModel):
    full_name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str
    confirm_password: str
    accept_terms: bool

    @field_validator("full_name")
    @classmethod
    def _name(cls, v):
        v = v.strip()
        if len(v) < 2:
            raise ValueError("Name is too short")
        return v


class VerifyIn(BaseModel):
    email: EmailStr
    otp: str = Field(pattern=r"^\d{6}$")


class EmailIn(BaseModel):
    email: EmailStr


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)
    remember_me: bool = False


class ResetIn(BaseModel):
    token: str = Field(min_length=20, max_length=200)
    password: str
    confirm_password: str


class TokenIn(BaseModel):
    token: str = Field(min_length=20, max_length=200)


# ---------------- registration ----------------
def _issue_challenge(db: Session, pending: PendingRegistration, resend_count: int = 0) -> tuple[EmailVerificationChallenge, str]:
    s = get_settings()
    db.execute(update(EmailVerificationChallenge)
               .where(EmailVerificationChallenge.pending_id == pending.id, EmailVerificationChallenge.consumed == False)  # noqa: E712
               .values(superseded=True))
    otp = generate_otp()
    ch = EmailVerificationChallenge(pending_id=pending.id, otp_digest=hmac_digest(otp, f"otp:{pending.id}"),
                                    expires_at=utcnow() + timedelta(seconds=s.OTP_EXPIRY_SECONDS),
                                    resend_count=resend_count)
    db.add(ch)
    db.flush()
    return ch, otp


def _send_otp(pending: PendingRegistration, otp: str):
    s = get_settings()
    es.send_email(es.otp_email(pending.email, pending.full_name, otp, max(1, s.OTP_EXPIRY_SECONDS // 60)))


def _cleanup_expired(db: Session):
    now = utcnow()
    ids = [r for r in db.execute(select(PendingRegistration.id).where(PendingRegistration.expires_at < now)).scalars()]
    if ids:
        db.execute(delete(EmailVerificationChallenge).where(EmailVerificationChallenge.pending_id.in_(ids)))
        db.execute(delete(PendingRegistration).where(PendingRegistration.id.in_(ids)))
    db.execute(delete(PasswordResetToken).where(PasswordResetToken.expires_at < now - timedelta(days=1)))
    db.execute(delete(UserSession).where(UserSession.expires_at < now - timedelta(days=1)))
    db.commit()


def _latest_challenge(db: Session, pending_id: str):
    return db.execute(select(EmailVerificationChallenge).where(EmailVerificationChallenge.pending_id == pending_id)
                      .order_by(EmailVerificationChallenge.created_at.desc())).scalars().first()


@router.post("/register", status_code=202)
def register(body: RegisterIn, request: Request, db: Session = Depends(get_db)):
    s = get_settings()
    email = normalize_email(body.email)
    ip = client_ip(request)
    enforce("register", s.RATE_LIMIT_REGISTER, ip, email)
    if not body.accept_terms:
        raise HTTPException(422, "You must accept the Terms and Privacy Policy.")
    if body.password != body.confirm_password:
        raise HTTPException(422, "Passwords do not match.")
    _check_pw(body.password)
    _cleanup_expired(db)

    resp = {"message": GENERIC_REGISTER, "email": mask_email(email),
            "otp_expires_in": s.OTP_EXPIRY_SECONDS, "resend_cooldown": s.OTP_RESEND_COOLDOWN_SECONDS}

    existing = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if existing:
        # Do not reveal that the account exists; notify the real owner instead.
        try:
            es.send_email(es.security_notice_email(
                existing.email, existing.full_name,
                "Someone tried to register with your email address. If it was you, sign in or use 'Forgot password'."))
        except es.EmailDeliveryError:
            pass
        log_event(db, "auth.register_duplicate", resource_type="user", resource_id=existing.id, security=True, ip=ip)
        return resp

    pending = db.execute(select(PendingRegistration).where(PendingRegistration.email == email)).scalar_one_or_none()
    resend_count = 0
    if pending:
        last = _latest_challenge(db, pending.id)
        if last:
            wait = s.OTP_RESEND_COOLDOWN_SECONDS - (utcnow() - _aware(last.created_at)).total_seconds()
            if wait > 0:
                resp["resend_cooldown"] = int(wait) + 1
                return resp
            resend_count = last.resend_count + 1
            if resend_count > s.OTP_MAX_RESENDS:
                raise HTTPException(429, "Too many verification requests. Please try again later.")
        pending.full_name, pending.password_hash = body.full_name, hash_password(body.password)
        pending.expires_at = utcnow() + timedelta(hours=1)
    else:
        pending = PendingRegistration(email=email, full_name=body.full_name, password_hash=hash_password(body.password),
                                      expires_at=utcnow() + timedelta(hours=1))
        db.add(pending)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            return resp
    ch, otp = _issue_challenge(db, pending, resend_count)
    db.commit()
    try:
        _send_otp(pending, otp)
    except es.EmailDeliveryError as e:
        log_event(db, "auth.otp_email_failed", resource_type="pending", resource_id=pending.id, security=True, ip=ip,
                  detail={"retryable": e.retryable})
        raise HTTPException(502, "We could not send the verification email. Please try again shortly.")
    log_event(db, "auth.register_otp_sent", resource_type="pending", resource_id=pending.id, ip=ip)
    return resp


@router.post("/resend-otp")
def resend_otp(body: EmailIn, request: Request, db: Session = Depends(get_db)):
    s = get_settings()
    email = normalize_email(body.email)
    ip = client_ip(request)
    enforce("otp_resend", s.RATE_LIMIT_OTP_RESEND, ip, email)
    resp = {"message": GENERIC_REGISTER, "otp_expires_in": s.OTP_EXPIRY_SECONDS,
            "resend_cooldown": s.OTP_RESEND_COOLDOWN_SECONDS}
    pending = db.execute(select(PendingRegistration).where(PendingRegistration.email == email)).scalar_one_or_none()
    if not pending or _aware(pending.expires_at) < utcnow():
        return resp
    last = _latest_challenge(db, pending.id)
    resend_count = 0
    if last:
        wait = s.OTP_RESEND_COOLDOWN_SECONDS - (utcnow() - _aware(last.created_at)).total_seconds()
        if wait > 0:
            raise HTTPException(429, f"Please wait {int(wait) + 1} seconds before requesting another code.",
                                headers={"Retry-After": str(int(wait) + 1)})
        resend_count = last.resend_count + 1
        if resend_count > s.OTP_MAX_RESENDS:
            raise HTTPException(429, "Maximum resend limit reached. Please register again later.")
    ch, otp = _issue_challenge(db, pending, resend_count)
    db.commit()
    try:
        _send_otp(pending, otp)
    except es.EmailDeliveryError:
        raise HTTPException(502, "We could not send the verification email. Please try again shortly.")
    log_event(db, "auth.otp_resent", resource_type="pending", resource_id=pending.id, ip=ip)
    return resp


@router.post("/verify-email")
def verify_email(body: VerifyIn, request: Request, db: Session = Depends(get_db)):
    s = get_settings()
    email = normalize_email(body.email)
    ip = client_ip(request)
    enforce("otp_verify", s.RATE_LIMIT_OTP_VERIFY, ip, email)
    bad = HTTPException(400, "Invalid or expired verification code.")
    pending = db.execute(select(PendingRegistration).where(PendingRegistration.email == email)
                         .with_for_update()).scalar_one_or_none()
    if not pending:
        raise bad
    ch = db.execute(select(EmailVerificationChallenge).where(
        EmailVerificationChallenge.pending_id == pending.id, EmailVerificationChallenge.consumed == False,  # noqa: E712
        EmailVerificationChallenge.superseded == False)  # noqa: E712
        .order_by(EmailVerificationChallenge.created_at.desc()).with_for_update()).scalars().first()
    if not ch:
        raise bad
    if _aware(ch.expires_at) < utcnow():
        raise HTTPException(410, "This verification code has expired. Request a new one.")
    if ch.attempts >= s.OTP_MAX_ATTEMPTS:
        raise HTTPException(429, "Too many incorrect attempts. Request a new code.")
    ok = digests_equal(ch.otp_digest, hmac_digest(body.otp, f"otp:{pending.id}"))
    if not ok:
        ch.attempts += 1
        left = s.OTP_MAX_ATTEMPTS - ch.attempts
        db.commit()
        log_event(db, "auth.otp_failed", resource_type="pending", resource_id=pending.id, security=True, ip=ip)
        if left <= 0:
            raise HTTPException(429, "Too many incorrect attempts. Request a new code.")
        raise HTTPException(400, f"Incorrect verification code. {left} attempt(s) remaining.")
    # success: create user transactionally
    role = "admin" if s.FIRST_ADMIN_EMAIL and normalize_email(s.FIRST_ADMIN_EMAIL) == email else "analyst"
    user = User(email=email, full_name=pending.full_name, password_hash=pending.password_hash, role=role,
                is_verified=True)
    ch.consumed = True
    db.add(user)
    try:
        db.flush()
        db.execute(delete(EmailVerificationChallenge).where(EmailVerificationChallenge.pending_id == pending.id))
        db.execute(delete(PendingRegistration).where(PendingRegistration.id == pending.id))
        db.commit()
    except IntegrityError:
        db.rollback()
        raise bad
    log_event(db, "auth.email_verified", actor_id=user.id, resource_type="user", resource_id=user.id, ip=ip)
    notify(db, "New user registered", f"{user.full_name} verified their account.", "info")
    return {"message": "Email verified. You can now sign in."}


# ---------------- login / session ----------------
def _set_cookies(resp: Response, access: str, refresh: str, csrf: str, remember: bool):
    s = get_settings()
    secure = s.is_prod
    resp.set_cookie(ACCESS_COOKIE, access, httponly=True, secure=secure, samesite="lax",
                    max_age=s.ACCESS_TOKEN_EXPIRE_MINUTES * 60, path="/")
    rmax = (s.REMEMBER_ME_REFRESH_DAYS if remember else None)
    resp.set_cookie(REFRESH_COOKIE, refresh, httponly=True, secure=secure, samesite="lax",
                    max_age=rmax * 86400 if rmax else None, path="/api/auth")
    resp.set_cookie(CSRF_COOKIE, csrf, httponly=False, secure=secure, samesite="lax",
                    max_age=rmax * 86400 if rmax else None, path="/")


def _clear_cookies(resp: Response):
    for name, path in ((ACCESS_COOKIE, "/"), (REFRESH_COOKIE, "/api/auth"), (CSRF_COOKIE, "/")):
        resp.delete_cookie(name, path=path)


def user_out(u: User) -> dict:
    perms = ROLE_PERMS.get(u.role, set())
    return {"id": u.id, "email": u.email, "full_name": u.full_name, "role": u.role,
            "permissions": sorted(perms), "is_verified": u.is_verified}


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    s = get_settings()
    email = normalize_email(body.email)
    ip = client_ip(request)
    enforce("login", s.RATE_LIMIT_LOGIN, ip, email)
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    ok = verify_password(body.password, user.password_hash if user else _DUMMY_HASH)
    if not user or not ok:
        log_event(db, "auth.login_failed", security=True, ip=ip, detail={"email_hash": hmac_digest(email, "audit")[:16]})
        raise HTTPException(401, "Incorrect email or password.")
    if not user.is_verified:
        raise HTTPException(403, "Please verify your email before signing in.")
    if not user.is_active:
        raise HTTPException(403, "This account has been disabled.")
    refresh, csrf = random_token(), random_token(24)
    days = s.REMEMBER_ME_REFRESH_DAYS if body.remember_me else s.REFRESH_TOKEN_EXPIRE_DAYS
    sess = UserSession(user_id=user.id, refresh_digest=hmac_digest(refresh, "refresh"),
                       csrf_digest=hmac_digest(csrf, "csrf"), expires_at=utcnow() + timedelta(days=days),
                       user_agent=request.headers.get("user-agent", "")[:255])
    db.add(sess)
    user.last_login_at = utcnow()
    db.commit()
    access = create_access_token(user.id, user.role, sess.id)
    _set_cookies(response, access, refresh, csrf, body.remember_me)
    log_event(db, "auth.login", actor_id=user.id, resource_type="user", resource_id=user.id, ip=ip)
    return {"user": user_out(user)}


@router.post("/refresh")
def refresh(request: Request, response: Response, db: Session = Depends(get_db)):
    token = request.cookies.get(REFRESH_COOKIE)
    if not token:
        raise HTTPException(401, "Not authenticated")
    sess = db.execute(select(UserSession).where(UserSession.refresh_digest == hmac_digest(token, "refresh"))
                      ).scalar_one_or_none()
    if not sess or sess.revoked or _aware(sess.expires_at) < utcnow():
        _clear_cookies(response)
        raise HTTPException(401, "Session expired")
    check_csrf(request, sess)
    user = db.get(User, sess.user_id)
    if not user or not user.is_active or not user.is_verified:
        raise HTTPException(401, "Account not available")
    new_refresh, new_csrf = random_token(), random_token(24)
    sess.refresh_digest = hmac_digest(new_refresh, "refresh")
    sess.csrf_digest = hmac_digest(new_csrf, "csrf")
    db.commit()
    remember = request.cookies.get(CSRF_COOKIE) is not None and (_aware(sess.expires_at) - utcnow()).days > get_settings().REFRESH_TOKEN_EXPIRE_DAYS
    _set_cookies(response, create_access_token(user.id, user.role, sess.id), new_refresh, new_csrf, remember)
    return {"user": user_out(user)}


@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    token = request.cookies.get(REFRESH_COOKIE)
    if token:
        sess = db.execute(select(UserSession).where(UserSession.refresh_digest == hmac_digest(token, "refresh"))
                          ).scalar_one_or_none()
        if sess:
            check_csrf(request, sess)
            sess.revoked = True
            db.commit()
            log_event(db, "auth.logout", actor_id=sess.user_id, ip=client_ip(request))
    _clear_cookies(response)
    return {"message": "Signed out."}


@router.get("/me")
def me(user: User = Depends(current_user)):
    return {"user": user_out(user)}


# ---------------- password reset ----------------
@router.post("/forgot-password")
def forgot_password(body: EmailIn, request: Request, db: Session = Depends(get_db)):
    s = get_settings()
    email = normalize_email(body.email)
    ip = client_ip(request)
    enforce("forgot", s.RATE_LIMIT_FORGOT, ip, email)
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if user and user.is_verified and user.is_active:
        db.execute(update(PasswordResetToken).where(PasswordResetToken.user_id == user.id,
                                                    PasswordResetToken.used == False).values(used=True))  # noqa: E712
        token = random_token(32)
        db.add(PasswordResetToken(user_id=user.id, token_digest=hmac_digest(token, "reset"),
                                  expires_at=utcnow() + timedelta(seconds=s.PASSWORD_RESET_EXPIRY_SECONDS)))
        db.commit()
        url = f"{s.FRONTEND_URL.rstrip('/')}/reset-password#token={token}"
        try:
            es.send_email(es.reset_email(user.email, user.full_name, url, max(1, s.PASSWORD_RESET_EXPIRY_SECONDS // 60)))
            log_event(db, "auth.reset_requested", actor_id=user.id, security=True, ip=ip)
        except es.EmailDeliveryError as e:
            log_event(db, "auth.reset_email_failed", actor_id=user.id, security=True, ip=ip, detail={"retryable": e.retryable})
    return {"message": GENERIC_FORGOT}


def _valid_reset(db: Session, token: str, lock: bool = False):
    q = select(PasswordResetToken).where(PasswordResetToken.token_digest == hmac_digest(token, "reset"))
    if lock:
        q = q.with_for_update()
    rt = db.execute(q).scalar_one_or_none()
    if not rt or rt.used or _aware(rt.expires_at) < utcnow():
        return None
    return rt


@router.post("/validate-reset-token")
def validate_reset_token(body: TokenIn, request: Request, db: Session = Depends(get_db)):
    enforce("reset_validate", get_settings().RATE_LIMIT_OTP_VERIFY, client_ip(request))
    if not _valid_reset(db, body.token):
        raise HTTPException(400, "This reset link is invalid or has expired.")
    return {"valid": True}


@router.post("/reset-password")
def reset_password(body: ResetIn, request: Request, db: Session = Depends(get_db)):
    s = get_settings()
    ip = client_ip(request)
    enforce("reset_submit", s.RATE_LIMIT_OTP_VERIFY, ip)
    if body.password != body.confirm_password:
        raise HTTPException(422, "Passwords do not match.")
    _check_pw(body.password)
    rt = _valid_reset(db, body.token, lock=True)
    if not rt:
        raise HTTPException(400, "This reset link is invalid or has expired.")
    user = db.get(User, rt.user_id)
    if not user:
        raise HTTPException(400, "This reset link is invalid or has expired.")
    user.password_hash = hash_password(body.password)
    rt.used = True
    db.execute(update(UserSession).where(UserSession.user_id == user.id).values(revoked=True))
    db.commit()
    log_event(db, "auth.password_reset", actor_id=user.id, resource_type="user", resource_id=user.id, security=True, ip=ip)
    try:
        es.send_email(es.reset_confirmation_email(user.email, user.full_name))
    except es.EmailDeliveryError:
        log.warning("reset confirmation email failed")
    return {"message": "Password updated. Please sign in with your new password."}
