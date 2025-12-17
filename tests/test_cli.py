from __future__ import annotations

import json
from typing import Any

from typer.testing import CliRunner

from acp_cli import main as cli


def test_execute_uses_env_bearer(monkeypatch):
    runner = CliRunner()
    captured: dict[str, Any] = {}

    class DummyClient:
        def __init__(self, base_url: str, api_key: str, bearer_token: str | None = None, **_: Any):
            captured["base_url"] = base_url
            captured["api_key"] = api_key
            captured["bearer"] = bearer_token

        async def execute_tool(self, *_: Any, **__: Any):
            return {"status": "SUCCESS"}

        async def close(self) -> None:
            return None

    monkeypatch.setattr(cli, "AgentControlPlaneClient", DummyClient)
    result = runner.invoke(
        cli.app,
        ["execute", "--api-key", "k", "--tool", "echo", "--args", "{}"],
        env={"MCP_FIREWALL_TOKEN": "abc"},
    )
    assert result.exit_code == 0
    assert captured["bearer"] == "abc"


def test_approve_can_generate_dev_token(monkeypatch):
    runner = CliRunner()
    captured: dict[str, Any] = {}

    class DummyClient:
        def __init__(self, base_url: str, api_key: str, bearer_token: str | None = None, **_: Any):
            captured["bearer"] = bearer_token

        async def approve(self, *_: Any, **__: Any):
            return {"status": "ok"}

        async def close(self) -> None:
            return None

    monkeypatch.setattr(cli, "AgentControlPlaneClient", DummyClient)
    result = runner.invoke(
        cli.app,
        [
            "approve",
            "--approval-id",
            "abc",
            "--token",
            "tok",
            "--approver",
            "me",
            "--dev-token",
        ],
        env={"MCP_FIREWALL_DEV_SECRET": "secret"},
    )
    assert result.exit_code == 0
    assert captured["bearer"] is not None
    payload = json.loads(result.stdout.strip().replace("'", '"'))
    assert payload["status"] == "ok"
