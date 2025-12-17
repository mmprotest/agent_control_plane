from __future__ import annotations

import json

from fastapi.testclient import TestClient


def test_execute_denied_on_policy(client: TestClient):
    response = client.post(
        "/v1/tool/execute",
        headers={"X-API-Key": "test-key"},
        json={"tool_name": "secret_fetch", "args": {}, "purpose": "exfiltration"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "DENIED"


def test_execute_requires_approval(client: TestClient):
    response = client.post(
        "/v1/tool/execute",
        headers={"X-API-Key": "test-key"},
        json={"tool_name": "sum_numbers", "args": {"numbers": [1, 2, 3]}},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "PENDING"


