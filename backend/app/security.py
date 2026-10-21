import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

from .config import get_settings

_ph = PasswordHasher()


def normalize_email(email: str) -> str:
    return email.strip().lower()


def hash_password(pw: str) -> str:
    return _ph.hash(pw)


def verify_password(pw: str, hashed: str) -> bool:
    try:
        return _ph.verify(hashed, pw)
    except (VerifyMismatchError, InvalidHashError):
        return False


def password_problems(pw: str) -> list[str]:
    p = []
    if len(pw) < 10:
        p.append("at least 10 characters")
    if len(pw) > 128:
        p.append("at most 128 characters")
    if not re.search(r"[a-z]", pw):
        p.append("a lowercase letter")
    if not re.search(r"[A-Z]", pw):
        p.append("an uppercase letter")
    if not re.search(r"\d", pw):
        p.append("a digit")
    if not re.search(r"[^A-Za-z0-9]", pw):
        p.append("a special character")
    return p


def generate_otp() -> str:
    return f"{secrets.randbelow(10**6):06d}"


def hmac_digest(value: str, purpose: str) -> str:
    key = get_settings().APP_SECRET_KEY.encode()
    return hmac.new(key, f"{purpose}:{value}".encode(), hashlib.sha256).hexdigest()


def digests_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def random_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def create_access_token(user_id: str, role: str, session_id: str) -> str:
    s = get_settings()
    exp = datetime.now(timezone.utc) + timedelta(minutes=s.ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode({"sub": user_id, "role": role, "sid": session_id, "exp": exp, "typ": "access"},
                      s.SESSION_SECRET, algorithm="HS256")


def decode_access_token(token: str) -> dict | None:
    try:
        d = jwt.decode(token, get_settings().SESSION_SECRET, algorithms=["HS256"])
        return d if d.get("typ") == "access" else None
    except jwt.PyJWTError:
        return None
