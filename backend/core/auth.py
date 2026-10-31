"""
AEGIS 2.0 — Authentication & Session Context

Handles:
- Ephemeral session IDs for regular/anonymous users.
- Enterprise user authentication, JWT-style signed tokens, and organization context.
- Organization data isolation (prevent cross-tenant access).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Optional

from fastapi import Header, HTTPException, status

from config import settings


# Secret used for signing auth tokens (can be set in .env)
AUTH_SECRET_KEY = getattr(settings, "auth_secret_key", "aegis-secret-key-phase3-dev-only")


@dataclass
class AuthContext:
    """Security and tenant context for the current request."""
    is_enterprise: bool
    session_id: str
    user_id: Optional[str] = None
    org_id: Optional[str] = None
    org_name: Optional[str] = None
    user_email: Optional[str] = None
    role: Optional[str] = None

    @property
    def storage_mode(self) -> str:
        return "enterprise" if self.is_enterprise else "session"


def generate_session_id() -> str:
    """Generate an unpredictable, cryptographically strong session ID."""
    return f"ses_{secrets.token_urlsafe(24)}"


def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    """Hash a password using PBKDF2-HMAC-SHA256."""
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000,
    ).hex()
    return hashed, salt


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    """Verify a password against stored salt and hash using constant-time comparison."""
    hashed, _ = hash_password(password, salt)
    return hmac.compare_digest(hashed, expected_hash)


def create_enterprise_token(user_id: str, org_id: str, email: str, role: str, expires_in_seconds: int = 86400) -> str:
    """Generate a tamper-proof HMAC-SHA256 signed token containing enterprise claims."""
    payload = {
        "sub": user_id,
        "org_id": org_id,
        "email": email,
        "role": role,
        "exp": int(time.time()) + expires_in_seconds,
        "iat": int(time.time()),
    }
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8").rstrip("=")
    signature = hmac.new(
        AUTH_SECRET_KEY.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{payload_b64}.{signature}"


def verify_enterprise_token(token: str) -> Optional[dict]:
    """Verify signature and expiration of an enterprise token."""
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None
        payload_b64, signature = parts
        expected_sig = hmac.new(
            AUTH_SECRET_KEY.encode("utf-8"),
            payload_b64.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature, expected_sig):
            return None

        # Add padding back if necessary
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8"))

        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None

