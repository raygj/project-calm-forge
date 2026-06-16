"""JWT validation for CALM Forge API.

Validates Bearer tokens against a JWKS endpoint (Vault or any OIDC provider).

Configuration (environment variables):
  CALM_FORGE_JWKS_URL   JWKS endpoint (required when auth enabled)
  CALM_FORGE_JWT_ISS    Expected issuer claim (optional)
  CALM_FORGE_JWT_AUD    Expected audience claim (optional)
  CALM_FORGE_NO_AUTH    Set to 'true' to disable auth (local dev)
"""
import os

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_AUTH_DISABLED: bool = os.getenv("CALM_FORGE_NO_AUTH", "").lower() in ("true", "1", "yes")
_JWKS_URL: str = os.getenv("CALM_FORGE_JWKS_URL", "")
_JWT_ISS: str = os.getenv("CALM_FORGE_JWT_ISS", "")
_JWT_AUD: str = os.getenv("CALM_FORGE_JWT_AUD", "")

_bearer = HTTPBearer(auto_error=False)


def disable_auth() -> None:
    """Disable JWT validation (called by --no-auth CLI flag)."""
    global _AUTH_DISABLED
    _AUTH_DISABLED = True


def enable_auth() -> None:
    """Re-enable JWT validation (used in tests)."""
    global _AUTH_DISABLED
    _AUTH_DISABLED = False


def set_jwks_url(url: str) -> None:
    """Set JWKS URL (used in tests)."""
    global _JWKS_URL
    _JWKS_URL = url


def verify_jwt(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> None:
    """FastAPI dependency — validates Bearer JWT or passes if auth disabled."""
    if _AUTH_DISABLED:
        return

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not _JWKS_URL:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Auth misconfigured: CALM_FORGE_JWKS_URL not set",
        )

    try:
        jwks_client = jwt.PyJWKClient(_JWKS_URL)
        signing_key = jwks_client.get_signing_key_from_jwt(credentials.credentials)
        jwt.decode(
            credentials.credentials,
            signing_key.key,
            algorithms=["RS256"],
            issuer=_JWT_ISS or None,
            audience=_JWT_AUD or None,
            options={"verify_aud": bool(_JWT_AUD)},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
