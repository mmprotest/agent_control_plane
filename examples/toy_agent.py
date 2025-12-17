"""
Toy agent walkthrough for MCP Firewall.

Environment variables:
- MCP_FIREWALL_URL: Base URL for the API (default: http://localhost:8000)
- MCP_FIREWALL_API_KEY: Agent API key (default: demo-key)
- MCP_FIREWALL_TOKEN: Optional bearer token; if absent, a dev token is generated using MCP_FIREWALL_DEV_SECRET
- MCP_FIREWALL_DEV_SECRET: HS256 secret for dev tokens (default: dev-secret)
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Callable

from jose import jwt

from acp_sdk.client import AgentControlPlaneClient


def _dev_token_factory() -> str:
    secret = os.getenv("MCP_FIREWALL_DEV_SECRET", "dev-secret")
    now = int(time.time())
    payload = {
        "sub": "toy-agent",
        "tenant": "demo-tenant",
        "roles": ["operator"],
        "iss": "toy-agent",
        "aud": "mcp-firewall",
        "iat": int(now),
        "nbf": int(now),
        "exp": int(now) + 3600,
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def _bearer_provider() -> str:
    return os.getenv("MCP_FIREWALL_TOKEN") or _dev_token_factory()


async def main() -> None:
    base_url = os.getenv("MCP_FIREWALL_URL", "http://localhost:8000")
    api_key = os.getenv("MCP_FIREWALL_API_KEY", "demo-key")
    token_provider: Callable[[], str] = _bearer_provider
    client = AgentControlPlaneClient(
        base_url,
        api_key=api_key,
        bearer_token_provider=token_provider,
    )

    allowed = await client.execute_tool("echo", {"message": "hello"}, purpose="greeting")
    print("allowed echo:", json.dumps(allowed, indent=2))

    denied = await client.execute_tool("secret_fetch", {"leak": True}, purpose="exfiltration")
    print("denied attempt:", json.dumps(denied, indent=2))

    pending = await client.execute_tool("sum_numbers", {"numbers": [1, 2, 3]}, purpose="calc")
    print("approval required:", json.dumps(pending, indent=2))

    if pending.get("status") == "PENDING" and pending.get("approval_id"):
        approval_token = pending.get("approval_token") or pending.get("token")
        approval_id = pending["approval_id"]
        approved = await client.approve(approval_id, approval_token, approver="toy-operator")
        print("approval completed:", json.dumps(approved, indent=2))

        retried = await client.execute_tool(
            "sum_numbers", {"numbers": [1, 2, 3]}, approval_token=approval_token, purpose="calc"
        )
        print("retried with approval:", json.dumps(retried, indent=2))

        replay = await client.replay(
            retried.get("trace_id") or allowed.get("trace_id"), dry_run=True
        )
        print("replay dry-run:", json.dumps(replay, indent=2))

    await client.close()


if __name__ == "__main__":
    asyncio.run(main())
