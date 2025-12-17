from __future__ import annotations

import asyncio
from typing import Any, Dict

import typer

from acp_sdk.client import AgentControlPlaneClient

app = typer.Typer(help="Agent Control Plane CLI")


@app.command()
def execute(
    base_url: str = typer.Option("http://localhost:8000"),
    api_key: str = typer.Option(...),
    tool: str = typer.Option(..., help="Tool name"),
    args: str = typer.Option("{}", help="JSON payload for tool args"),
):
    import json

    async def _run() -> None:
        client = AgentControlPlaneClient(base_url, api_key)
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
