from __future__ import annotations

import asyncio
import json
import os
import time

os.environ.setdefault("POLICY_PATH", "examples/mcp_demo/policy.yaml")
os.environ.setdefault("DATABASE_URL", "sqlite:///./mcp_demo.db")

from jose import jwt  # noqa: E402
import httpx  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

from acp_backend.api import main  # noqa: E402
from acp_backend.core.config import get_settings  # noqa: E402
from acp_backend.core.security import hash_secret  # noqa: E402
from acp_backend.database import get_engine, init_db  # noqa: E402
from acp_backend.models.entities import Agent, Role, User  # noqa: E402
from acp_backend.tooling.mcp_connector import McpHttpConnector  # noqa: E402
from acp_sdk.client import AgentControlPlaneClient  # noqa: E402
from examples.mcp_demo.server import app as mcp_app  # noqa: E402


API_KEY = "demo-key"


def seed_demo_data() -> None:
    init_db()
    engine = get_engine()
    with Session(engine) as session:
        role = session.exec(select(Role).where(Role.name == "operator")).first()
        if not role:
            role = Role(name="operator", permissions=["echo", "blocked", "add"])
            session.add(role)
            session.commit()
            session.refresh(role)
        existing_agent = session.exec(select(Agent).where(Agent.name == "demo-agent")).first()
        if not existing_agent:
            agent = Agent(name="demo-agent", hashed_api_key=hash_secret(API_KEY), role_id=role.id)
            session.add(agent)
        existing_user = session.exec(select(User).where(User.email == "demo@example.com")).first()
        if not existing_user:
            user = User(email="demo@example.com", hashed_token=hash_secret("user-token"), role_id=role.id)
            session.add(user)
        session.commit()


def make_token() -> str:
    settings = get_settings()
    now = int(time.time())
    payload = {
        "sub": "demo-user",
        "tenant": "demo-tenant",
        "roles": ["operator"],
        "iat": now,
        "nbf": now,
        "exp": now + 3600,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


async def run_demo() -> None:
    seed_demo_data()
    token = make_token()
    firewall_transport = httpx.ASGITransport(app=main.app)
    mcp_transport = httpx.ASGITransport(app=mcp_app)

    def _client_factory(_: str) -> httpx.AsyncClient:
        return httpx.AsyncClient(base_url="http://mcp.local", transport=mcp_transport)

    main.mcp_connector = McpHttpConnector(client_factory=_client_factory)

    async with httpx.AsyncClient(transport=firewall_transport, base_url="http://firewall") as http_client:
        sdk = AgentControlPlaneClient(
            "http://firewall", api_key=API_KEY, bearer_token=token, httpx_client=http_client
        )
        register_resp = await sdk.register_mcp("http://mcp.local")
        print("Registered MCP tools:", json.dumps(register_resp, indent=2))

        allowed = await sdk.execute_tool("echo", {"text": "hello via MCP"})
        print("Allowed response:", json.dumps(allowed, indent=2))

        denied = await sdk.execute_tool("blocked", {})
        print("Denied response:", json.dumps(denied, indent=2))

        approval = await sdk.execute_tool("add", {"a": 2, "b": 3})
        print("Approval response:", json.dumps(approval, indent=2))

        audit_check = await sdk.verify_audit()
        print("Audit chain valid:", audit_check)

        await sdk.close()


if __name__ == "__main__":
    asyncio.run(run_demo())
