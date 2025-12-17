from __future__ import annotations

import time
from typing import Any, Dict
from unittest.mock import AsyncMock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jose import jwt
from jose.utils import base64url_encode

from acp_backend.core import auth
from acp_backend.core.config import get_settings


def test_missing_bearer_rejected(client: TestClient) -> None:
    response = client.post(
        "/v1/tool/execute",
        headers={"X-API-Key": "test-key"},
        json={"tool_name": "echo", "args": {"message": "hi"}},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "missing_bearer_token"


def test_invalid_roles_rejected(client: TestClient) -> None:
    # craft token with invalid role type
    token = client.app.extra["make_token"]()
    bad_token = client.app.extra["make_token"](roles="not-a-list")
    response = client.post(
        "/v1/tool/execute",
        headers={
            "X-API-Key": "test-key",
            "Authorization": f"Bearer {bad_token}",
        },
        json={"tool_name": "echo", "args": {"message": "hi"}},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_roles"

    ok_response = client.post(
        "/v1/tool/execute",
        headers={
            "X-API-Key": "test-key",
            "Authorization": f"Bearer {token}",
        },
        json={"tool_name": "echo", "args": {"message": "hi"}},
    )
    assert ok_response.status_code == 200


def test_expired_token_rejected(client: TestClient) -> None:
    settings = get_settings()
    now = int(time.time())
    expired = jwt.encode(
        {
            "sub": "tester",
            "tenant": "tenant-a",
            "roles": ["operator"],
            "iat": now - 7200,
            "nbf": now - 7200,
            "exp": now - 3600,
        },
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )
    response = client.post(
        "/v1/tool/execute",
        headers={"X-API-Key": "test-key", "Authorization": f"Bearer {expired}"},
        json={"tool_name": "echo", "args": {"message": "hi"}},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_token"


def test_wrong_audience_rejected(client: TestClient) -> None:
    settings = get_settings()
    settings.jwt_audience = "expected-aud"
    now = int(time.time())
    wrong_aud = jwt.encode(
        {
            "sub": "tester",
            "tenant": "tenant-a",
            "roles": ["operator"],
            "aud": "other",
            "iat": now,
            "nbf": now,
            "exp": now + 60,
        },
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )
    try:
        response = client.post(
            "/v1/tool/execute",
            headers={"X-API-Key": "test-key", "Authorization": f"Bearer {wrong_aud}"},
            json={"tool_name": "echo", "args": {"message": "hi"}},
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "invalid_token"
    finally:
        settings.jwt_audience = None


def test_wrong_issuer_rejected(client: TestClient) -> None:
    settings = get_settings()
    settings.jwt_issuer = "expected-iss"
    now = int(time.time())
    wrong_iss = jwt.encode(
        {
            "sub": "tester",
            "tenant": "tenant-a",
            "roles": ["operator"],
            "iss": "other",  # wrong issuer
            "iat": now,
            "nbf": now,
            "exp": now + 60,
        },
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )
    try:
        response = client.post(
            "/v1/tool/execute",
            headers={"X-API-Key": "test-key", "Authorization": f"Bearer {wrong_iss}"},
            json={"tool_name": "echo", "args": {"message": "hi"}},
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "invalid_token"
    finally:
        settings.jwt_issuer = None


def _generate_rsa_keypair() -> tuple[bytes, Dict[str, Any]]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_numbers = private_key.public_key().public_numbers()
    n = base64url_encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big"))
    e = base64url_encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, "big"))
    jwk_dict: Dict[str, Any] = {"kty": "RSA", "kid": "test-key", "alg": "RS256", "n": n, "e": e}
    return private_pem, jwk_dict


def test_missing_kid_rejected_with_jwks(client: TestClient) -> None:
    settings = get_settings()
    settings.oidc_jwks_url = "https://issuer.example/jwks"
    settings.jwks_cache_ttl_seconds = 0
    try:
        private_key, jwk_dict = _generate_rsa_keypair()
        jwks = {"keys": [jwk_dict]}

        async def fake_fetch(url: str) -> Dict[str, Any]:  # noqa: ARG001
            return jwks

        now = int(time.time())
        token = jwt.encode(
            {
                "sub": "tester",
                "tenant": "tenant-a",
                "roles": ["operator"],
                "iat": now,
                "nbf": now,
                "exp": now + 60,
            },
            private_key,
            algorithm="RS256",
            headers={},
        )

        with patch.object(auth, "_fetch_jwks", AsyncMock(side_effect=fake_fetch)):
            response = client.post(
                "/v1/tool/execute",
                headers={"X-API-Key": "test-key", "Authorization": f"Bearer {token}"},
                json={"tool_name": "echo", "args": {"message": "hi"}},
            )
        assert response.status_code == 401
        assert response.json()["detail"] == "missing_kid"
    finally:
        settings.oidc_jwks_url = None
        settings.jwks_cache_ttl_seconds = 300


def test_jwks_rotation_refreshes_cache(client: TestClient) -> None:
    settings = get_settings()
    settings.oidc_jwks_url = "https://issuer.example/jwks"
    settings.jwks_cache_ttl_seconds = 0

    private_key1, jwk_dict1 = _generate_rsa_keypair()
    private_key2, jwk_dict2 = _generate_rsa_keypair()

    jwks_sets = [{"keys": [jwk_dict1]}, {"keys": [jwk_dict2]}]
    fetch_mock = AsyncMock(side_effect=jwks_sets)

    now = int(time.time())

    token1 = jwt.encode(
        {
            "sub": "tester",
            "tenant": "tenant-a",
            "roles": ["operator"],
            "iat": now,
            "nbf": now,
            "exp": now + 60,
        },
        private_key1,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )

    token2 = jwt.encode(
        {
            "sub": "tester",
            "tenant": "tenant-a",
            "roles": ["operator"],
            "iat": now,
            "nbf": now,
            "exp": now + 60,
        },
        private_key2,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )

    try:
        with patch.object(auth, "_fetch_jwks", fetch_mock):
            first = client.post(
                "/v1/tool/execute",
                headers={"X-API-Key": "test-key", "Authorization": f"Bearer {token1}"},
                json={"tool_name": "echo", "args": {"message": "hi"}},
            )
            assert first.status_code == 200

            second = client.post(
                "/v1/tool/execute",
                headers={"X-API-Key": "test-key", "Authorization": f"Bearer {token2}"},
                json={"tool_name": "echo", "args": {"message": "hi"}},
            )
            assert second.status_code == 200
            assert fetch_mock.await_count == 2
    finally:
        settings.oidc_jwks_url = None
        settings.jwks_cache_ttl_seconds = 300
