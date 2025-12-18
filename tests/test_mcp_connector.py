from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlmodel import select

from acp_backend.api import main
from acp_backend.models.entities import AuditLogEntry, Role, Trace
from acp_backend.tooling.mcp_connector import McpHttpConnector


@pytest.fixture
def fake_mcp_app() -> FastAPI:
    app = FastAPI()

    @app.get("/mcp/tools")
    async def list_tools():
        return {"tools": [{"name": "echo"}, {"name": "blocked"}]}

    @app.post("/mcp/tools/echo")
    async def echo(payload: dict):
        return {"echo": payload}

    @app.post("/mcp/tools/blocked")
    async def blocked(payload: dict):
        return {"error": "blocked"}

    return app


@pytest.fixture
def patched_connector(fake_mcp_app: FastAPI):
    transport = httpx.ASGITransport(app=fake_mcp_app)

    def _client_factory(base_url: str) -> httpx.AsyncClient:
        return httpx.AsyncClient(base_url=base_url, transport=transport)

    connector = McpHttpConnector(client_factory=_client_factory)
    original = main.mcp_connector
    main.mcp_connector = connector
    yield connector
    main.mcp_connector = original


def test_mcp_register_and_execute(client: TestClient, patched_connector, session):
    token = client.app.extra["make_token"]()
    role = session.exec(select(Role).where(Role.name == "operator")).one()
    if "blocked" not in role.permissions:
        role.permissions.append("blocked")
    session.add(role)
    session.commit()
    resp = client.post(
        "/v1/mcp/register",
        headers={"Authorization": f"Bearer {token}", "X-API-Key": "test-key"},
        json={"base_url": "http://mcp.test"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "echo" in body["registered"]

    exec_resp = client.post(
        "/v1/tool/execute",
        headers={"Authorization": f"Bearer {token}", "X-API-Key": "test-key"},
        json={"tool_name": "echo", "args": {"message": "hi from mcp"}},
    )
    assert exec_resp.status_code == 200
    exec_body = exec_resp.json()
    assert exec_body["status"] in {"SUCCESS", "ALLOWED"}
    assert exec_body.get("explanation", {}).get("decision") == "allow"
    trace = session.exec(select(Trace).order_by(Trace.created_at.desc())).first()
    assert trace and trace.policy_decision.get("explanation")


def test_mcp_policy_denies(client: TestClient, patched_connector, session):
    token = client.app.extra["make_token"]()
    role = session.exec(select(Role).where(Role.name == "operator")).one()
    if "blocked" not in role.permissions:
        role.permissions.append("blocked")
    session.add(role)
    session.commit()
    main.policy_engine.rules = [
        {"tool": "blocked", "decision": "deny", "id": "deny-blocked"},
        {"tool": "echo", "decision": "allow"},
    ]
    client.post(
        "/v1/mcp/register",
        headers={"Authorization": f"Bearer {token}", "X-API-Key": "test-key"},
        json={"base_url": "http://mcp.test"},
    )

    exec_resp = client.post(
        "/v1/tool/execute",
        headers={"Authorization": f"Bearer {token}", "X-API-Key": "test-key"},
        json={"tool_name": "blocked", "args": {"message": "deny me"}},
    )
    assert exec_resp.status_code == 200
    exec_body = exec_resp.json()
    assert exec_body["status"] == "DENIED"
    assert exec_body.get("explanation", {}).get("matched_rule_id") == "deny-blocked"
    audit_entry = session.exec(select(AuditLogEntry).order_by(AuditLogEntry.id.desc())).first()
    assert audit_entry and audit_entry.details.get("policy_explanation")
