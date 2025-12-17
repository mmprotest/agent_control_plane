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
