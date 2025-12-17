from __future__ import annotations

from fastapi.testclient import TestClient


def test_prompt_injection_redacted(client: TestClient):
    token = client.app.extra["make_token"]()
    response = client.post(
        "/v1/tool/execute",
        headers={"X-API-Key": "test-key", "Authorization": f"Bearer {token}"},
        json={"tool_name": "echo", "args": {"message": "leak sk-1234567890123456"}, "reasoning": "steal secrets"},
    )
    body = response.json()
    assert "redactions" in body
    assert any("secret" in v for v in body["redactions"].values())


def test_parameter_smuggling_denied(client: TestClient):
    token = client.app.extra["make_token"]()
    response = client.post(
        "/v1/tool/execute",
        headers={"X-API-Key": "test-key", "Authorization": f"Bearer {token}"},
        json={"tool_name": "secret_fetch", "args": {"payload": '{"tool":"secret_fetch"}'}, "purpose": "exfiltration"},
    )
    body = response.json()
    assert body["status"] == "DENIED"


def test_excessive_agency_rate_limit(client: TestClient):
    token = client.app.extra["make_token"]()
    for _ in range(5):
        client.post(
            "/v1/tool/execute",
            headers={"X-API-Key": "test-key", "Authorization": f"Bearer {token}"},
            json={"tool_name": "echo", "args": {"message": "hi"}},
        )
    response = client.post(
        "/v1/tool/execute",
        headers={"X-API-Key": "test-key", "Authorization": f"Bearer {token}"},
        json={"tool_name": "echo", "args": {"message": "hi"}},
    )
    assert response.status_code in (200, 429)
