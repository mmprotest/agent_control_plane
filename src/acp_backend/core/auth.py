from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx
from fastapi import Header, HTTPException, Request
from jose import JWTError, jwk, jwt

from acp_backend.core.config import get_settings


@dataclass
class AuthContext:
    principal_id: str
    tenant_id: str
    roles: list[str]
    agent_id: Optional[str]
    raw_claims: Dict[str, Any]


class AuthError(HTTPException):
    def __init__(self, code: str, status_code: int = 401) -> None:
        super().__init__(status_code=status_code, detail=code)


async def _fetch_jwks(jwks_url: str) -> Dict[str, Any]:
    async with httpx.AsyncClient() as client:
        response = await client.get(jwks_url)
        response.raise_for_status()
        return response.json()


def _verify_with_jwks(token: str, jwks: Dict[str, Any], audience: Optional[str], issuer: Optional[str]) -> Dict[str, Any]:
    headers = jwt.get_unverified_header(token)
    kid = headers.get("kid")
    keys = jwks.get("keys", [])
    key_data = next((k for k in keys if k.get("kid") == kid), None)
    if not key_data:
        raise AuthError("invalid_kid")
    key = jwk.construct(key_data)
    message, encoded_sig = jwt._load(token)  # type: ignore[attr-defined]
    if not key.verify(message, encoded_sig):
        raise AuthError("invalid_signature")
    claims = jwt.get_unverified_claims(token)
    if audience and claims.get("aud") != audience:
        raise AuthError("invalid_audience")
    if issuer and claims.get("iss") != issuer:
        raise AuthError("invalid_issuer")
    return claims


def _verify_hs256(token: str, secret: str, audience: Optional[str], issuer: Optional[str]) -> Dict[str, Any]:
    try:
        return jwt.decode(token, secret, algorithms=["HS256"], audience=audience, issuer=issuer)
    except JWTError as exc:  # noqa: BLE001
        raise AuthError("invalid_token") from exc


async def require_auth(
    request: Request,
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> AuthContext:
    settings = get_settings()
    if not authorization or not authorization.startswith("Bearer "):
        raise AuthError("missing_bearer_token")
    token = authorization.removeprefix("Bearer ").strip()

    claims: Dict[str, Any]
    if settings.oidc_jwks_url:
        jwks = await _fetch_jwks(settings.oidc_jwks_url)
        claims = _verify_with_jwks(token, jwks, settings.jwt_audience, settings.jwt_issuer)
    else:
        claims = _verify_hs256(token, settings.jwt_secret, settings.jwt_audience, settings.jwt_issuer)

    principal_id = claims.get("sub") or claims.get("principal_id")
    tenant_id = claims.get("tenant") or claims.get("tenant_id")
    roles = claims.get("roles") or []
    agent_id = claims.get("agent_id")
    if not principal_id or not tenant_id:
        raise AuthError("missing_identity")
    if not isinstance(roles, list):
        raise AuthError("invalid_roles")

    request.state.auth_context = AuthContext(
        principal_id=str(principal_id),
        tenant_id=str(tenant_id),
        roles=[str(r) for r in roles],
        agent_id=str(agent_id) if agent_id else None,
        raw_claims=claims,
    )
    return request.state.auth_context
