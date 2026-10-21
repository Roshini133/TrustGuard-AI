import os
import re
import tempfile

_tmp = tempfile.mkdtemp()
os.environ.update({
    "APP_ENV": "test", "APP_SECRET_KEY": "test-secret-key-test-secret-key-12345",
    "SESSION_SECRET": "test-session-secret-test-session-123456", "DATABASE_URL": os.environ.get("TEST_DATABASE_URL", f"sqlite:///{_tmp}/test.db"),
    "ARTIFACT_STORAGE_PATH": f"{_tmp}/artifacts", "JOBS_MODE": "sync", "REDIS_URL": "",
    "OTP_RESEND_COOLDOWN_SECONDS": "60", "FRONTEND_URL": "https://app.example.com",
    "RATE_LIMIT_REGISTER": "1000/60", "RATE_LIMIT_LOGIN": "1000/60", "RATE_LIMIT_OTP_VERIFY": "1000/60",
    "RATE_LIMIT_OTP_RESEND": "1000/60", "RATE_LIMIT_FORGOT": "1000/60", "FIRST_ADMIN_EMAIL": "admin@example.com",
})

import pytest
from fastapi.testclient import TestClient

from app import email_service as es
from app.db import Base, SessionLocal, engine
from app.main import app
from app.ratelimit import reset_memory


class MockProvider(es.EmailProvider):
    """Isolated test double. Production code never uses this."""
    def __init__(self):
        self.sent: list[es.Email] = []
        self.fail = False

    def send(self, email):
        if self.fail:
            raise es.EmailDeliveryError("boom")
        self.sent.append(email)
        return "mock-id"

    def last_otp(self, to):
        for e in reversed(self.sent):
            if e.to == to:
                m = re.search(r"code is: (\d{6})", e.text)
                if m:
                    return m.group(1)

    def last_reset_token(self, to):
        for e in reversed(self.sent):
            if e.to == to:
                m = re.search(r"#token=([\w-]+)", e.text)
                if m:
                    return m.group(1)


@pytest.fixture(autouse=True)
def _fresh():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    reset_memory()
    yield


@pytest.fixture
def mail():
    p = MockProvider()
    es.set_provider(p)
    yield p
    es.set_provider(None)


@pytest.fixture
def client():
    with TestClient(app, base_url="https://testserver") as c:
        yield c


@pytest.fixture
def db():
    d = SessionLocal()
    yield d
    d.close()


PW = "Str0ng!Passw0rd"


def register_and_verify(client, mail, email="user@example.com", name="Test User", pw=PW):
    r = client.post("/api/auth/register", json={"full_name": name, "email": email, "password": pw,
                                                 "confirm_password": pw, "accept_terms": True})
    assert r.status_code == 202, r.text
    otp = mail.last_otp(email.lower())
    r = client.post("/api/auth/verify-email", json={"email": email, "otp": otp})
    assert r.status_code == 200, r.text


def login(client, email="user@example.com", pw=PW, remember=False):
    r = client.post("/api/auth/login", json={"email": email, "password": pw, "remember_me": remember})
    assert r.status_code == 200, r.text
    return r


def hdr(client):
    return {"X-CSRF-Token": client.cookies.get("tg_csrf")}


@pytest.fixture
def user_client(client, mail):
    register_and_verify(client, mail)
    login(client)
    return client


@pytest.fixture
def admin_client(mail):
    with TestClient(app, base_url="https://testserver") as c:
        register_and_verify(c, mail, email="admin@example.com", name="Admin")
        login(c, email="admin@example.com")
        yield c
