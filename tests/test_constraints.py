from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlmodel import select

from acp_backend.api import main
from acp_backend.models.entities import Role, Tool
from acp_backend.services.rate_limit import RateLimiter


def _auth_headers(client: TestClient) -> dict[str, str]:
    token = client.app.extra["make_token"]()
    return {"X-API-Key": "test-key", "Authorization": f"Bearer {token}"}


def test_rbac_blocks_before_policy(client: TestClient, session) -> None:
    role = session.exec(select(Role).where(Role.name == "operator")).one()
    role.permissions = ["echo"]
    session.add(role)
    session.commit()
    main.policy_engine.rules = [{"tool": "sum_numbers", "role": "operator", "decision": "allow"}]
    response = client.post(
        "/v1/tool/execute",
        headers=_auth_headers(client),
        json={"tool_name": "sum_numbers", "args": {"numbers": [1]}, "purpose": "calc"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "DENIED"
    assert body["message"] == "agent_role_denied"


def test_policy_denies_even_if_rbac_allows(client: TestClient, session) -> None:
    role = session.exec(select(Role).where(Role.name == "operator")).one()
    role.permissions = ["echo", "secret_fetch"]
    session.add(role)
    session.commit()
    main.policy_engine.rules = [
        {"tool": "secret_fetch", "role": "operator", "decision": "deny", "purpose": "exfiltration"}
    ]
    response = client.post(
        "/v1/tool/execute",
        headers=_auth_headers(client),
        json={"tool_name": "secret_fetch", "args": {}, "purpose": "exfiltration"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "DENIED"


def test_domain_allow_and_deny_constraints(client: TestClient, session, monkeypatch) -> None:
    role = session.exec(select(Role).where(Role.name == "operator")).one()
    role.permissions.append("fetch_api")
    session.add(role)
    session.commit()
    session.add(Tool(name="fetch_api", type="http", endpoint="https://allowed.example.com/api"))
    session.commit()
    main.policy_engine.rules = [
        {
            "tool": "fetch_api",
            "role": "operator",
            "decision": "allow",
            "constraints": {
                "allow_domains": ["allowed.example.com"],
                "deny_domains": ["blocked.example.com"],
            },
        }
    ]

    async def fake_execute(endpoint: str, args: dict[str, Any], *_: Any) -> dict[str, Any]:
        return {"endpoint": endpoint, "args": args}

    monkeypatch.setattr(main.http_connector, "execute", fake_execute)

    ok_response = client.post(
        "/v1/tool/execute",
        headers=_auth_headers(client),
        json={"tool_name": "fetch_api", "args": {}},
    )
    assert ok_response.json()["status"] == "SUCCESS"

    session.add(Tool(name="blocked_api", type="http", endpoint="https://blocked.example.com/api"))
    session.commit()
    role.permissions.append("blocked_api")
    session.add(role)
    session.commit()
    main.policy_engine.rules = [
        {
            "tool": "blocked_api",
            "role": "operator",
            "decision": "allow",
            "constraints": {
                "allow_domains": ["allowed.example.com"],
                "deny_domains": ["blocked.example.com"],
            },
        }
    ]
    deny_response = client.post(
        "/v1/tool/execute",
        headers=_auth_headers(client),
        json={"tool_name": "blocked_api", "args": {}},
    )
    assert deny_response.json()["status"] == "DENIED"
    assert deny_response.json()["message"] == "domain_denied"


def test_domain_alias_and_denied_domain_wins(client: TestClient, session, monkeypatch) -> None:
    role = session.exec(select(Role).where(Role.name == "operator")).one()
    role.permissions.append("fetch_api")
    session.add(role)
    session.commit()
    session.add(Tool(name="fetch_api", type="http", endpoint="https://denied.example.com"))
    session.commit()

    main.policy_engine.rules = [
        {
            "tool": "fetch_api",
            "role": "operator",
            "decision": "allow",
            "constraints": {
                "allowed_domains": ["denied.example.com"],
                "deny_domains": ["denied.example.com"],
            },
        }
    ]

    async def fake_execute(endpoint: str, args: dict[str, Any], *_: Any) -> dict[str, Any]:
        return {"endpoint": endpoint, "args": args}

    monkeypatch.setattr(main.http_connector, "execute", fake_execute)

    response = client.post(
        "/v1/tool/execute",
        headers=_auth_headers(client),
        json={"tool_name": "fetch_api", "args": {}},
    )
    assert response.json()["status"] == "DENIED"
    assert response.json()["message"] == "domain_denied"


def test_domain_parsing_handles_userinfo(client: TestClient, session, monkeypatch) -> None:
    role = session.exec(select(Role).where(Role.name == "operator")).one()
    role.permissions.append("tricky_api")
    session.add(role)
    session.commit()
    session.add(Tool(name="tricky_api", type="http", endpoint="https://good.com@evil.com/path"))
    session.commit()

    main.policy_engine.rules = [
        {
            "tool": "tricky_api",
            "role": "operator",
            "decision": "allow",
            "constraints": {"allow_domains": ["good.com"], "deny_domains": ["evil.com"]},
        }
    ]

    async def fake_execute(endpoint: str, args: dict[str, Any], *_: Any) -> dict[str, Any]:
        return {"endpoint": endpoint, "args": args}

    monkeypatch.setattr(main.http_connector, "execute", fake_execute)

    response = client.post(
        "/v1/tool/execute",
        headers=_auth_headers(client),
        json={"tool_name": "tricky_api", "args": {}},
    )
    assert response.json()["status"] == "DENIED"
    assert response.json()["message"] == "domain_denied"


def test_max_bytes_args_and_output(client: TestClient, session) -> None:
    main.policy_engine.rules = [
        {"tool": "echo", "role": "operator", "decision": "allow", "constraints": {"max_bytes": 20}}
    ]
    big_args = {"message": "x" * 50}
    first = client.post(
        "/v1/tool/execute",
        headers=_auth_headers(client),
        json={"tool_name": "echo", "args": big_args},
    )
    assert first.json()["status"] == "DENIED"
    assert first.json()["message"] == "max_bytes_exceeded"

    main.internal_tools.register("big_output", lambda _: {"data": "y" * 50})
    session.add(Tool(name="big_output", type="internal"))
    session.commit()
    role = session.exec(select(Role).where(Role.name == "operator")).one()
    role.permissions.append("big_output")
    session.add(role)
    session.commit()
    main.policy_engine.rules = [
        {
            "tool": "big_output",
            "role": "operator",
            "decision": "allow",
            "constraints": {"max_bytes": 10},
        }
    ]
    ok_args = {"message": "ok"}
    output_response = client.post(
        "/v1/tool/execute",
        headers=_auth_headers(client),
        json={"tool_name": "big_output", "args": ok_args},
    )
    assert output_response.json()["status"] == "DENIED"
    assert output_response.json()["message"] == "max_bytes_exceeded"
    main.internal_tools._tools.pop("big_output", None)


def test_per_tool_rate_limit(client: TestClient) -> None:
    class Clock:
        def __init__(self) -> None:
            self.now = 0.0

        def __call__(self) -> float:
            return self.now

        def tick(self, seconds: float) -> None:
            self.now += seconds

    clock = Clock()
    main.rate_limiter = RateLimiter(time_fn=clock)
    main.policy_engine.rules = [
        {
            "tool": "echo",
            "role": "operator",
            "decision": "allow",
            "constraints": {"max_calls_per_minute": 1},
        }
    ]

    headers = _auth_headers(client)
    first = client.post(
        "/v1/tool/execute",
        headers=headers,
        json={"tool_name": "echo", "args": {"message": "hi"}},
    )
    assert first.json()["status"] == "SUCCESS"

    second = client.post(
        "/v1/tool/execute",
        headers=headers,
        json={"tool_name": "echo", "args": {"message": "hi again"}},
    )
    assert second.json()["status"] == "DENIED"
    assert second.json()["message"] == "rate_limited"

    clock.tick(61)
    third = client.post(
        "/v1/tool/execute",
        headers=headers,
        json={"tool_name": "echo", "args": {"message": "after window"}},
    )
    assert third.json()["status"] == "SUCCESS"


def test_rate_limit_alias_key(client: TestClient) -> None:
    class Clock:
        def __init__(self) -> None:
            self.now = 0.0

        def __call__(self) -> float:
            return self.now

    clock = Clock()
    main.rate_limiter = RateLimiter(time_fn=clock)
    main.policy_engine.rules = [
        {
            "tool": "echo",
            "decision": "allow",
            "constraints": {"rate_limit_per_minute": 1},
        }
    ]

    headers = _auth_headers(client)
    first = client.post(
        "/v1/tool/execute",
        headers=headers,
        json={"tool_name": "echo", "args": {"message": "hi"}},
    )
    assert first.json()["status"] == "SUCCESS"

    second = client.post(
        "/v1/tool/execute",
        headers=headers,
        json={"tool_name": "echo", "args": {"message": "hi again"}},
    )
    assert second.json()["status"] == "DENIED"
    assert second.json()["message"] == "rate_limited"
