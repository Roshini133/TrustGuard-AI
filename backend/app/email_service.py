"""Email abstraction. Production uses Resend only; no fake success path in production."""
import html
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass

from .config import get_settings

log = logging.getLogger("trustguard.email")


class EmailDeliveryError(Exception):
    def __init__(self, message: str, retryable: bool = True):
        super().__init__(message)
        self.retryable = retryable


@dataclass
class Email:
    to: str
    subject: str
    html: str
    text: str


class EmailProvider(ABC):
    @abstractmethod
    def send(self, email: Email) -> str: ...


class ResendProvider(EmailProvider):
    def send(self, email: Email) -> str:
        import resend
        s = get_settings()
        if not s.RESEND_API_KEY or not s.EMAIL_FROM:
            raise EmailDeliveryError("Email provider is not configured", retryable=False)
        resend.api_key = s.RESEND_API_KEY
        try:
            res = resend.Emails.send({
                "from": s.EMAIL_FROM, "to": [email.to], "subject": email.subject,
                "html": email.html, "text": email.text,
            })
        except Exception as e:  # SDK raises typed errors; map generically without leaking details
            name = type(e).__name__
            log.error("resend send failed: %s", name)
            retry = name not in ("ValidationError", "MissingApiKeyError", "InvalidApiKeyError")
            raise EmailDeliveryError(f"Email provider error: {name}", retryable=retry) from e
        mid = (res or {}).get("id") if isinstance(res, dict) else getattr(res, "id", None)
        if not mid:
            raise EmailDeliveryError("Email provider did not accept the message")
        log.info("email accepted by provider id=%s", mid)
        return mid


class ConsoleProvider(EmailProvider):
    """Development only. Refused in production by config validation."""

    def send(self, email: Email) -> str:
        if get_settings().is_prod:
            raise EmailDeliveryError("Console provider is disabled in production", retryable=False)
        print(f"[DEV EMAIL] to={email.to} subject={email.subject}\n{email.text}\n")
        return "console"


_provider_override: EmailProvider | None = None


def set_provider(p: EmailProvider | None):
    """Used by isolated automated tests only."""
    global _provider_override
    _provider_override = p


def get_provider() -> EmailProvider:
    if _provider_override is not None:
        return _provider_override
    s = get_settings()
    if s.EMAIL_PROVIDER == "console" and not s.is_prod:
        return ConsoleProvider()
    return ResendProvider()


def send_email(email: Email) -> str:
    return get_provider().send(email)


# ---------- templates ----------
def _layout(title: str, body_html: str) -> str:
    return f"""<!doctype html><html><body style="margin:0;background:#F8FAFC;font-family:Segoe UI,Arial,sans-serif;color:#1E293B">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:24px 12px">
<table width="100%" style="max-width:520px;background:#fff;border:1px solid #DBEAFE;border-radius:12px;overflow:hidden" cellpadding="0" cellspacing="0">
<tr><td style="background:#1E3A8A;padding:20px 28px;color:#fff;font-size:20px;font-weight:700">&#128737; TrustGuard AI</td></tr>
<tr><td style="padding:28px"><h1 style="margin:0 0 12px;font-size:20px;color:#0F172A">{html.escape(title)}</h1>{body_html}
<p style="margin-top:28px;padding:12px;background:#EFF6FF;border-radius:8px;font-size:13px;color:#64748B">Never share this code or link with anyone. TrustGuard AI staff will never ask for it. If you did not request this, you can safely ignore this email.</p>
</td></tr></table></td></tr></table></body></html>"""


def otp_email(to: str, name: str, otp: str, minutes: int) -> Email:
    body = (f'<p>Hi {html.escape(name)},</p><p>Use this code to verify your email address:</p>'
            f'<p style="font-size:34px;letter-spacing:8px;font-weight:700;color:#2563EB;background:#EFF6FF;'
            f'text-align:center;padding:16px;border-radius:10px">{otp}</p>'
            f'<p>This code expires in {minutes} minute(s).</p>')
    text = (f"Hi {name},\n\nYour TrustGuard AI verification code is: {otp}\n"
            f"It expires in {minutes} minute(s). Do not share it with anyone.\n")
    return Email(to, "Your TrustGuard AI verification code", _layout("Verify your email", body), text)


def reset_email(to: str, name: str, url: str, minutes: int) -> Email:
    u = html.escape(url, quote=True)
    body = (f'<p>Hi {html.escape(name)},</p><p>We received a request to reset your password.</p>'
            f'<p style="text-align:center"><a href="{u}" style="background:#2563EB;color:#fff;padding:12px 24px;'
            f'border-radius:8px;text-decoration:none;font-weight:600;display:inline-block">Reset password</a></p>'
            f'<p style="font-size:13px;color:#64748B">Or paste this link into your browser:<br>{u}</p>'
            f'<p>This link expires in {minutes} minute(s) and can be used once.</p>')
    text = (f"Hi {name},\n\nReset your TrustGuard AI password using this link (expires in {minutes} minutes, single use):\n"
            f"{url}\n\nIf you did not request this, ignore this email.\n")
    return Email(to, "Reset your TrustGuard AI password", _layout("Reset your password", body), text)


def reset_confirmation_email(to: str, name: str) -> Email:
    body = (f'<p>Hi {html.escape(name)},</p><p>Your password was changed successfully. '
            f'All existing sessions were signed out.</p>'
            f'<p>If this was not you, reset your password immediately and contact your administrator.</p>')
    text = f"Hi {name},\n\nYour TrustGuard AI password was changed. All sessions were signed out.\nIf this was not you, reset it immediately.\n"
    return Email(to, "Your TrustGuard AI password was changed", _layout("Password changed", body), text)


def security_notice_email(to: str, name: str, message: str) -> Email:
    body = f'<p>Hi {html.escape(name)},</p><p>{html.escape(message)}</p>'
    return Email(to, "TrustGuard AI security notice", _layout("Security notice", body), f"Hi {name},\n\n{message}\n")
