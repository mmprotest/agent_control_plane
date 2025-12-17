from __future__ import annotations

from fastapi.testclient import TestClient


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
