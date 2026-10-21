from datetime import timedelta

from sqlalchemy import select

from app.models import (EmailVerificationChallenge, PasswordResetToken, PendingRegistration, User, UserSession)
from app.ratelimit import reset_memory
from app.routers.auth import utcnow
from .conftest import PW, hdr, login, register_and_verify

BODY = {"full_name": "Test User", "email": "user@example.com", "password": PW, "confirm_password": PW, "accept_terms": True}


def test_registration_sends_real_email_through_provider(client, mail, db):
    r = client.post("/api/auth/register", json=BODY)
    assert r.status_code == 202
    assert len(mail.sent) == 1 and mail.sent[0].to == "user@example.com"
    otp = mail.last_otp("user@example.com")
    assert otp and len(otp) == 6 and otp.isdigit()
    assert otp not in r.text                      # never echoed to the browser
    ch = db.execute(select(EmailVerificationChallenge)).scalar_one()
    assert otp not in ch.otp_digest and len(ch.otp_digest) == 64   # stored as keyed digest
    assert db.execute(select(User)).first() is None   # not a user until verified


def test_validation_errors(client, mail):
    assert client.post("/api/auth/register", json={**BODY, "password": "weak", "confirm_password": "weak"}).status_code == 422
    assert client.post("/api/auth/register", json={**BODY, "confirm_password": PW + "x"}).status_code == 422
    assert client.post("/api/auth/register", json={**BODY, "accept_terms": False}).status_code == 422
    assert client.post("/api/auth/register", json={**BODY, "email": "not-an-email"}).status_code == 422
    assert mail.sent == []


def test_correct_otp_verifies_and_login_works(client, mail, db):
    register_and_verify(client, mail)
    u = db.execute(select(User)).scalar_one()
    assert u.is_verified and u.email == "user@example.com"
    assert db.execute(select(PendingRegistration)).first() is None
    login(client)
    assert client.get("/api/auth/me").json()["user"]["email"] == "user@example.com"


def test_email_normalization_and_duplicate(client, mail, db):
    register_and_verify(client, mail, email="User@Example.com")
    n = len(mail.sent)
    r = client.post("/api/auth/register", json={**BODY, "email": " USER@example.COM "})
    assert r.status_code == 202                               # generic response, no enumeration
    assert db.execute(select(User)).scalars().all().__len__() == 1
    assert "no longer" not in r.text and mail.sent[n].subject == "TrustGuard AI security notice"


def test_incorrect_otp_rejected_and_attempt_limit(client, mail):
    client.post("/api/auth/register", json=BODY)
    good = mail.last_otp("user@example.com")
    bad = "000000" if good != "000000" else "111111"
    for i in range(4):
        r = client.post("/api/auth/verify-email", json={"email": BODY["email"], "otp": bad})
        assert r.status_code == 400
    r = client.post("/api/auth/verify-email", json={"email": BODY["email"], "otp": bad})
    assert r.status_code == 429
    # even the correct OTP is now refused: attempts exhausted
    r = client.post("/api/auth/verify-email", json={"email": BODY["email"], "otp": good})
    assert r.status_code == 429


def test_expired_otp(client, mail, db):
    client.post("/api/auth/register", json=BODY)
    otp = mail.last_otp("user@example.com")
    ch = db.execute(select(EmailVerificationChallenge)).scalar_one()
    ch.expires_at = utcnow() - timedelta(seconds=1)
    db.commit()
    r = client.post("/api/auth/verify-email", json={"email": BODY["email"], "otp": otp})
    assert r.status_code == 410


def test_otp_replay_rejected(client, mail):
    client.post("/api/auth/register", json=BODY)
    otp = mail.last_otp("user@example.com")
    assert client.post("/api/auth/verify-email", json={"email": BODY["email"], "otp": otp}).status_code == 200
    assert client.post("/api/auth/verify-email", json={"email": BODY["email"], "otp": otp}).status_code == 400


def test_resend_cooldown_and_supersede(client, mail, db):
    client.post("/api/auth/register", json=BODY)
    first = mail.last_otp("user@example.com")
    r = client.post("/api/auth/resend-otp", json={"email": BODY["email"]})
    assert r.status_code == 429                                  # within 60s cooldown
    ch = db.execute(select(EmailVerificationChallenge)).scalar_one()
    ch.created_at = utcnow() - timedelta(seconds=61)
    db.commit()
    assert client.post("/api/auth/resend-otp", json={"email": BODY["email"]}).status_code == 200
    second = mail.last_otp("user@example.com")
    if first != second:   # superseded OTP must not work
        assert client.post("/api/auth/verify-email", json={"email": BODY["email"], "otp": first}).status_code == 400
    assert client.post("/api/auth/verify-email", json={"email": BODY["email"], "otp": second}).status_code == 200


def test_email_failure_does_not_verify(client, mail, db):
    mail.fail = True
    r = client.post("/api/auth/register", json=BODY)
    assert r.status_code == 502
    assert db.execute(select(User)).first() is None
    mail.fail = False   # safe retry via resend after cooldown
    ch = db.execute(select(EmailVerificationChallenge)).scalar_one()
    ch.created_at = utcnow() - timedelta(seconds=61)
    db.commit()
    assert client.post("/api/auth/resend-otp", json={"email": BODY["email"]}).status_code == 200


def test_unverified_cannot_login(client, mail):
    client.post("/api/auth/register", json=BODY)
    r = client.post("/api/auth/login", json={"email": BODY["email"], "password": PW})
    assert r.status_code == 401        # not a user yet


def test_rate_limit_register(client, mail, monkeypatch):
    from app import config
    monkeypatch.setenv("RATE_LIMIT_REGISTER", "2/60")
    config.get_settings.cache_clear()
    try:
        codes = [client.post("/api/auth/register", json={**BODY, "email": f"a{i}@example.com"}).status_code for i in range(4)]
        assert 429 in codes
    finally:
        monkeypatch.delenv("RATE_LIMIT_REGISTER")
        config.get_settings.cache_clear()
        reset_memory()


def test_login_failures_and_protected_routes(client, mail):
    register_and_verify(client, mail)
    assert client.post("/api/auth/login", json={"email": "user@example.com", "password": "Wrong!Pass123"}).status_code == 401
    assert client.post("/api/auth/login", json={"email": "nobody@example.com", "password": PW}).status_code == 401
    assert client.get("/api/datasets").status_code == 401
    assert client.get("/api/dashboard").status_code == 401
    assert client.get("/api/auth/me").status_code == 401


def test_logout_revokes_session_and_csrf(client, mail):
    register_and_verify(client, mail)
    login(client)
    assert client.post("/api/auth/logout").status_code == 403          # missing CSRF header
    h = hdr(client)
    token = client.cookies.get("tg_access")
    assert client.post("/api/auth/logout", headers=h).status_code == 200
    assert client.get("/api/auth/me").status_code == 401
    # old access token no longer valid even if replayed
    client.cookies.set("tg_access", token)
    assert client.get("/api/auth/me").status_code == 401


def test_refresh_rotates(client, mail):
    register_and_verify(client, mail)
    login(client)
    old = client.cookies.get("tg_refresh")
    r = client.post("/api/auth/refresh", headers=hdr(client))
    assert r.status_code == 200
    assert client.cookies.get("tg_refresh") != old
    client.cookies.set("tg_refresh", old, path="/api/auth")
    assert client.post("/api/auth/refresh", headers=hdr(client)).status_code == 401   # reuse of old refresh token


def test_forgot_password_generic_and_reset_flow(client, mail, db):
    register_and_verify(client, mail)
    login(client)
    r1 = client.post("/api/auth/forgot-password", json={"email": "user@example.com"})
    r2 = client.post("/api/auth/forgot-password", json={"email": "ghost@example.com"})
    assert r1.status_code == r2.status_code == 200 and r1.json() == r2.json()
    assert all(e.to != "ghost@example.com" for e in mail.sent)
    token = mail.last_reset_token("user@example.com")
    assert token and "app.example.com/reset-password#token=" in mail.sent[-1].text   # built from FRONTEND_URL
    row = db.execute(select(PasswordResetToken)).scalar_one()
    assert token not in row.token_digest
    assert client.post("/api/auth/validate-reset-token", json={"token": token}).status_code == 200
    newpw = "N3w!Passw0rd-xyz"
    assert client.post("/api/auth/reset-password", json={"token": token, "password": "short", "confirm_password": "short"}).status_code == 422
    assert client.post("/api/auth/reset-password", json={"token": token, "password": newpw, "confirm_password": newpw + "x"}).status_code == 422
    r = client.post("/api/auth/reset-password", json={"token": token, "password": newpw, "confirm_password": newpw})
    assert r.status_code == 200
    # replay rejected
    assert client.post("/api/auth/reset-password", json={"token": token, "password": newpw, "confirm_password": newpw}).status_code == 400
    # sessions revoked
    assert client.get("/api/auth/me").status_code == 401
    assert all(s.revoked for s in db.execute(select(UserSession)).scalars())
    # not auto-logged-in; old password fails, new works
    assert client.post("/api/auth/login", json={"email": "user@example.com", "password": PW}).status_code == 401
    login(client, pw=newpw)
    assert mail.sent[-1].subject.startswith("Your TrustGuard AI password was changed") or any(
        e.subject.startswith("Your TrustGuard AI password was changed") for e in mail.sent)


def test_expired_reset_token(client, mail, db):
    register_and_verify(client, mail)
    client.post("/api/auth/forgot-password", json={"email": "user@example.com"})
    token = mail.last_reset_token("user@example.com")
    row = db.execute(select(PasswordResetToken)).scalar_one()
    row.expires_at = utcnow() - timedelta(seconds=1)
    db.commit()
    assert client.post("/api/auth/validate-reset-token", json={"token": token}).status_code == 400
    assert client.post("/api/auth/reset-password", json={"token": token, "password": "N3w!Passw0rd-xyz", "confirm_password": "N3w!Passw0rd-xyz"}).status_code == 400


def test_new_reset_request_invalidates_previous(client, mail):
    register_and_verify(client, mail)
    client.post("/api/auth/forgot-password", json={"email": "user@example.com"})
    t1 = mail.last_reset_token("user@example.com")
    client.post("/api/auth/forgot-password", json={"email": "user@example.com"})
    assert client.post("/api/auth/validate-reset-token", json={"token": t1}).status_code == 400


def test_no_secrets_in_audit_log(client, mail, db):
    from app.models import AuditEvent
    register_and_verify(client, mail)
    client.post("/api/auth/forgot-password", json={"email": "user@example.com"})
    token, otp = mail.last_reset_token("user@example.com"), "x"
    blob = " ".join(str(e.detail) + e.action + e.resource_id for e in db.execute(select(AuditEvent)).scalars())
    assert token not in blob


def test_config_fails_safely_in_production():
    import pytest
    from app.config import Settings
    with pytest.raises(ValueError):
        Settings(APP_ENV="production", APP_SECRET_KEY="change-me", DATABASE_URL="postgresql://x/y")
    with pytest.raises(ValueError):
        Settings(APP_ENV="production", APP_SECRET_KEY="a" * 40, SESSION_SECRET="b" * 40, DATABASE_URL="postgresql://x/y",
                 EMAIL_PROVIDER="console", FRONTEND_URL="https://x.com")
    Settings(APP_ENV="production", APP_SECRET_KEY="a" * 40, SESSION_SECRET="b" * 40, DATABASE_URL="postgresql://x/y",
             RESEND_API_KEY="re_x", EMAIL_FROM="TrustGuard <no-reply@x.com>", FRONTEND_URL="https://x.com",
             CORS_ORIGINS="https://x.com")


def test_console_provider_refused_in_production(monkeypatch):
    import pytest
    from types import SimpleNamespace
    from app import email_service as es
    monkeypatch.setattr(es, "get_settings", lambda: SimpleNamespace(is_prod=True))
    with pytest.raises(es.EmailDeliveryError):
        es.ConsoleProvider().send(es.Email("a@b.com", "s", "h", "t"))
