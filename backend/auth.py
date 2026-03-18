"""
Simple JWT authentication for the DDoS Shield API.

Educational note:
  JSON Web Tokens (JWT) are a compact, URL-safe way to represent claims
  between two parties.  The flow:

  1. Client sends username + password to /api/auth/login.
  2. Server validates credentials, returns a signed JWT.
  3. Client sends the JWT in the Authorization header for subsequent requests.
  4. Server verifies the signature on each request — no session storage needed.

  **Security considerations for students:**
  - Never store JWTs in localStorage in production (XSS risk) — use httpOnly cookies.
  - Always use HTTPS so tokens can't be intercepted.
  - Keep token lifetimes short and implement refresh tokens for long sessions.
  - The secret key MUST be a strong random value in production.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import BaseModel

from config import config

# ---------------------------------------------------------------------------
# Password hashing (using bcrypt directly — passlib is unmaintained)
# ---------------------------------------------------------------------------


def _hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


# Pre-hash the default password so we can compare securely
_default_password_hash = _hash_password(config.auth.default_password)


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenData(BaseModel):
    username: str


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------

def create_access_token(username: str) -> str:
    """
    Create a signed JWT for the given user.

    Educational note:
      The payload contains the subject (username) and an expiration timestamp.
      jwt.encode signs the payload with our secret key using HS256 (HMAC-SHA256).
    """
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=config.auth.access_token_expire_minutes
    )
    payload = {"sub": username, "exp": expire}
    return jwt.encode(payload, config.auth.secret_key, algorithm=config.auth.algorithm)


def verify_password(plain: str, hashed: str) -> bool:
    return _verify_password(plain, hashed)


def authenticate_user(username: str, password: str) -> str | None:
    """
    Validate credentials and return the username, or None.

    For this educational project we use a single configurable user.
    A production system would query a user database here.
    """
    if username != config.auth.default_username:
        return None
    if not verify_password(password, _default_password_hash):
        return None
    return username


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


async def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    """
    FastAPI dependency that extracts and validates the JWT from the
    Authorization header.

    Raises 401 if the token is missing, expired, or invalid.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token, config.auth.secret_key, algorithms=[config.auth.algorithm]
        )
        username: str | None = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return username
