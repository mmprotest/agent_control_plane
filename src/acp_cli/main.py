from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any, Dict, Optional

import typer
from jose import jwt

from acp_sdk.client import AgentControlPlaneClient

app = typer.Typer(name="mcp-firewall", help="MCP Firewall CLI")
mcp_app = typer.Typer(name="mcp", help="MCP proxy utilities")
app.add_typer(mcp_app, name="mcp")


def _resolve_bearer_token(
    token: Optional[str], dev_token: bool, dev_secret: Optional[str]
) -> Optional[str]:
    if token:
        return token
    if not dev_token:
        return None
    secret = dev_secret or os.getenv("MCP_FIREWALL_DEV_SECRET", "dev-secret")
    now = int(time.time())
    payload = {
        "sub": "cli-user",
        "tenant": "dev-tenant",
        "roles": ["operator"],
        "iss": "mcp-firewall-cli",
        "aud": "mcp-firewall",
        "iat": int(now),
        "nbf": int(now),
        "exp": int(now) + 3600,
    }
    return jwt.encode(payload, secret, algorithm="HS256")


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
    dev_token: bool = typer.Option(
        False, help="Generate a dev token using MCP_FIREWALL_DEV_SECRET"
    ),
    dev_secret: Optional[str] = typer.Option(
        default_factory=lambda: os.getenv("MCP_FIREWALL_DEV_SECRET"),
        help="Dev HS256 secret for generating a short-lived token",
    ),
):
    async def _run() -> None:
        bearer = _resolve_bearer_token(token, dev_token, dev_secret)
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
    bearer: Optional[str] = typer.Option(
        default=None,
        help="Bearer token for Authorization header",
        envvar="MCP_FIREWALL_TOKEN",
    ),
    dev_token: bool = typer.Option(
        False, help="Generate a dev token using MCP_FIREWALL_DEV_SECRET"
    ),
    dev_secret: Optional[str] = typer.Option(
        default_factory=lambda: os.getenv("MCP_FIREWALL_DEV_SECRET"),
        help="Dev HS256 secret for generating a short-lived token",
    ),
):
    async def _run() -> None:
        resolved_bearer = _resolve_bearer_token(bearer, dev_token, dev_secret)
        client = AgentControlPlaneClient(
            base_url, api_key="cli-approver", bearer_token=resolved_bearer
        )
        result = await client.approve(approval_id, token, approver)
        typer.echo(result)
        await client.close()

    asyncio.run(_run())


@app.command()
def replay(
    base_url: str = typer.Option("http://localhost:8000"),
    trace_id: str = typer.Option(...),
    dry_run: bool = typer.Option(False, help="Perform a dry-run policy evaluation"),
    bearer: Optional[str] = typer.Option(
        default=None,
        help="Bearer token for Authorization header",
        envvar="MCP_FIREWALL_TOKEN",
    ),
    dev_token: bool = typer.Option(
        False, help="Generate a dev token using MCP_FIREWALL_DEV_SECRET"
    ),
    dev_secret: Optional[str] = typer.Option(
        default_factory=lambda: os.getenv("MCP_FIREWALL_DEV_SECRET"),
        help="Dev HS256 secret for generating a short-lived token",
    ),
):
    async def _run() -> None:
        resolved_bearer = _resolve_bearer_token(bearer, dev_token, dev_secret)
        client = AgentControlPlaneClient(
            base_url, api_key="cli-replay", bearer_token=resolved_bearer
        )
        result = await client.replay(trace_id, dry_run=dry_run)
        typer.echo(json.dumps(result, indent=2))
        await client.close()

    asyncio.run(_run())


@mcp_app.command("register")
def register_mcp(
    base_url: str = typer.Option("http://localhost:8000"),
    api_key: str = typer.Option(...),
    mcp_url: str = typer.Option(..., help="Base URL for MCP server"),
    tools: Optional[str] = typer.Option(None, help="Comma-separated tool names"),
    bearer: Optional[str] = typer.Option(default=None, envvar="MCP_FIREWALL_TOKEN"),
    dev_token: bool = typer.Option(False),
    dev_secret: Optional[str] = typer.Option(None, envvar="MCP_FIREWALL_DEV_SECRET"),
):
    async def _run() -> None:
        resolved_bearer = _resolve_bearer_token(bearer, dev_token, dev_secret)
        client = AgentControlPlaneClient(
            base_url, api_key=api_key, bearer_token=resolved_bearer
        )
        tool_list = tools.split(",") if tools else None
        result = await client.register_mcp(mcp_url, tools=tool_list)
        typer.echo(json.dumps(result, indent=2))
        await client.close()

    asyncio.run(_run())


@mcp_app.command("list-tools")
def list_mcp_tools(
    base_url: str = typer.Option("http://localhost:8000"),
    api_key: str = typer.Option(...),
    bearer: Optional[str] = typer.Option(default=None, envvar="MCP_FIREWALL_TOKEN"),
    dev_token: bool = typer.Option(False),
    dev_secret: Optional[str] = typer.Option(None, envvar="MCP_FIREWALL_DEV_SECRET"),
):
    async def _run() -> None:
        resolved_bearer = _resolve_bearer_token(bearer, dev_token, dev_secret)
        client = AgentControlPlaneClient(
            base_url, api_key=api_key, bearer_token=resolved_bearer
        )
        result = await client.list_mcp_tools()
        typer.echo(json.dumps(result, indent=2))
        await client.close()

    asyncio.run(_run())


@app.command()
def audit_verify(
    base_url: str = typer.Option("http://localhost:8000"),
    api_key: str = typer.Option(...),
    bearer: Optional[str] = typer.Option(default=None, envvar="MCP_FIREWALL_TOKEN"),
    dev_token: bool = typer.Option(False),
    dev_secret: Optional[str] = typer.Option(None, envvar="MCP_FIREWALL_DEV_SECRET"),
):
    async def _run() -> None:
        resolved_bearer = _resolve_bearer_token(bearer, dev_token, dev_secret)
        client = AgentControlPlaneClient(
            base_url, api_key=api_key, bearer_token=resolved_bearer
        )
        result = await client.verify_audit()
        typer.echo(json.dumps(result, indent=2))
        await client.close()

    asyncio.run(_run())


if __name__ == "__main__":
    app()
