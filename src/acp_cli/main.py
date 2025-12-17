from __future__ import annotations

import asyncio
import os
from typing import Any, Dict, Optional

import typer
from jose import jwt

from acp_sdk.client import AgentControlPlaneClient

app = typer.Typer(help="Agent Control Plane CLI")


def _maybe_generate_dev_token(dev_secret: Optional[str]) -> Optional[str]:
    if not dev_secret:
        return None
    now = int(asyncio.get_event_loop().time())
    payload = {
        "sub": "cli-user",
        "tenant": "dev-tenant",
        "roles": ["operator"],
        "iat": int(now),
        "nbf": int(now),
        "exp": int(now) + 3600,
    }
    return jwt.encode(payload, dev_secret, algorithm="HS256")


@app.command()
def execute(
    base_url: str = typer.Option("http://localhost:8000"),
    api_key: str = typer.Option(...),
    tool: str = typer.Option(..., help="Tool name"),
    args: str = typer.Option("{}", help="JSON payload for tool args"),
    token: Optional[str] = typer.Option(
        default=None,
        help="Bearer token for Authorization header",
        envvar="MCP_FIREWALL_TOKEN",
    ),
    dev_secret: Optional[str] = typer.Option(
        default_factory=lambda: os.getenv("MCP_FIREWALL_DEV_SECRET"),
        help="Dev HS256 secret for generating a short-lived token",
    ),
):
    import json

    async def _run() -> None:
        bearer = token or _maybe_generate_dev_token(dev_secret)
        client = AgentControlPlaneClient(base_url, api_key, bearer_token=bearer)
        payload: Dict[str, Any] = json.loads(args)
        result = await client.execute_tool(tool, payload)
        typer.echo(json.dumps(result, indent=2))
        await client.close()

    asyncio.run(_run())


@app.command()
def approve(
    base_url: str = typer.Option("http://localhost:8000"),
    approval_id: str = typer.Option(...),
    token: str = typer.Option(...),
    approver: str = typer.Option(...),
):
    async def _run() -> None:
        client = AgentControlPlaneClient(base_url, api_key="")
        result = await client.approve(approval_id, token, approver)
        typer.echo(result)
        await client.close()

    asyncio.run(_run())


if __name__ == "__main__":
    app()
