"""Security helpers: field encryption, security headers, TOTP MFA, lockout, CSV safety."""
import base64
import hashlib
import hmac
import os
import secrets
import struct
import time

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.cache import cache
from django.db import models


# ---------------------------------------------------------------- encryption
def _fernet():
    raw = settings.FIELD_ENCRYPTION_KEY or settings.SECRET_KEY
    key = base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest())
    return Fernet(key)


def encrypt_bytes(data: bytes) -> bytes:
    return _fernet().encrypt(data)


def decrypt_bytes(data: bytes) -> bytes:
    return _fernet().decrypt(data)


class EncryptedTextField(models.TextField):
    """Encrypts values with Fernet (AES-128-CBC + HMAC) before they hit the DB."""

    def get_prep_value(self, value):
        value = super().get_prep_value(value)
        if value in (None, ""):
            return value
        return _fernet().encrypt(value.encode()).decode()

    def from_db_value(self, value, expression, connection):
        if not value:
            return value
        try:
            return _fernet().decrypt(value.encode()).decode()
        except InvalidToken:
            return "[decryption-error]"


def mask_mobile(value: str) -> str:
    value = value or ""
    return ("*" * max(len(value) - 4, 0)) + value[-4:]


# ------------------------------------------------------------ HTTP headers
class SecurityHeadersMiddleware:
    """CSP + hardening headers (defence-in-depth against XSS / clickjacking)."""

    CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
           "frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none'")

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if not request.path.startswith("/admin-console/"):
            response.setdefault("Content-Security-Policy", self.CSP)
        response.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        if request.user.is_authenticated:
            response["Cache-Control"] = "no-store"  # never cache personal data
        return response


# ------------------------------------------------------------------ TOTP MFA
def new_totp_secret() -> str:
    return base64.b32encode(os.urandom(10)).decode()


def totp(secret: str, for_time=None, step=30, digits=6) -> str:
    key = base64.b32decode(secret, casefold=True)
    counter = int((for_time if for_time is not None else time.time()) // step)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def verify_totp(secret: str, code: str, window=1) -> bool:
    code = (code or "").strip()
    if not secret or not code.isdigit():
        return False
    now = time.time()
    return any(secrets.compare_digest(totp(secret, now + d * 30), code)
               for d in range(-window, window + 1))


# ------------------------------------------------------------ login lockout
def client_ip(request) -> str:
    return request.META.get("REMOTE_ADDR", "")


def _lock_key(username, ip):
    return "loginfail:%s:%s" % (hashlib.sha256((username or "").lower().encode()).hexdigest()[:20], ip)


def is_locked(username, ip) -> bool:
    return cache.get(_lock_key(username, ip), 0) >= settings.LOGIN_MAX_FAILURES


def register_failure(username, ip):
    key = _lock_key(username, ip)
    cache.set(key, cache.get(key, 0) + 1, settings.LOGIN_LOCKOUT_SECONDS)


def clear_failures(username, ip):
    cache.delete(_lock_key(username, ip))


# --------------------------------------------------------------- CSV safety
def csv_safe(value):
    """Neutralise spreadsheet formula injection in exported cells."""
    if value is None:
        return ""
    text = str(value)
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text
