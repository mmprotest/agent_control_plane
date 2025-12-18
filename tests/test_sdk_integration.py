from __future__ import annotations

import pytest
import httpx

from acp_sdk.client import AgentControlPlaneClient


@pytest.mark.asyncio
async def test_sdk_without_token_gets_401(client) -> None:
    from acp_backend.core.config import get_settings

    settings = get_settings()
    settings.oidc_jwks_url = None
    transport = httpx.ASGITransport(app=client.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as async_client:
        sdk = AgentControlPlaneClient(
            "http://test", api_key="test-key", httpx_client=async_client, bearer_token=None
        )
        with pytest.raises(httpx.HTTPStatusError):
            await sdk.execute_tool("echo", {"message": "hi"})


@pytest.mark.asyncio
async def test_sdk_with_token_succeeds(client) -> None:
    from acp_backend.core.config import get_settings

    settings = get_settings()
    settings.oidc_jwks_url = None
    token = client.app.extra["make_token"]()
    transport = httpx.ASGITransport(app=client.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as async_client:
        sdk = AgentControlPlaneClient(
            "http://test", api_key="test-key", httpx_client=async_client, bearer_token=token
        )
        resp = await sdk.execute_tool("echo", {"message": "hi"})
        assert resp["status"] in {"ALLOWED", "DENIED", "PENDING", "SUCCESS"}
        await sdk.close()


def test_header_builder_includes_auth_and_api_key():
    client = AgentControlPlaneClient("http://test", api_key="key", bearer_token="token")
    headers = client._build_headers()
    assert headers["Authorization"] == "Bearer token"
    assert headers["X-API-Key"] == "key"


@pytest.mark.asyncio
async def test_sdk_approval_and_replay_use_auth(client) -> None:
    from acp_backend.core.config import get_settings

    settings = get_settings()
    settings.oidc_jwks_url = None
    token = client.app.extra["make_token"]()
    transport = httpx.ASGITransport(app=client.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as async_client:
        sdk = AgentControlPlaneClient(
            "http://test", api_key="test-key", httpx_client=async_client, bearer_token=token
        )
        pending = await sdk.execute_tool("sum_numbers", {"numbers": [1, 2, 3]}, purpose="calc")
        approval_id = pending["approval_id"]
        approval_token = pending["approval_token"]
        approved = await sdk.approve(approval_id, approval_token, approver="tester")
        assert approved["status"] == "approved"

        final = await sdk.execute_tool(
            "sum_numbers", {"numbers": [1, 2, 3]}, approval_token=approval_token, purpose="calc"
        )
        assert final["status"] == "SUCCESS"
        assert final.get("explanation", {}).get("decision") == "allow"

        replay = await sdk.replay(final["trace_id"], dry_run=True)
        assert replay["trace_id"] == final["trace_id"]
        assert replay["dry_run_result"].get("explanation", {}).get("decision")
        await sdk.close()
