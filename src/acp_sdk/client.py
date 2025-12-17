from __future__ import annotations

from typing import Any, Callable, Dict, Optional

import httpx


class AgentControlPlaneClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        user_token: Optional[str] = None,
        bearer_token: str | None = None,
        bearer_token_provider: Callable[[], str] | None = None,
        httpx_client: httpx.AsyncClient | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.user_token = user_token
        self.bearer_token = bearer_token
        self.bearer_token_provider = bearer_token_provider
        self._client = httpx_client or httpx.AsyncClient(base_url=self.base_url)
        self._owns_client = httpx_client is None

    def _authorization_header(self) -> Dict[str, str]:
        token = self.bearer_token
        if self.bearer_token_provider:
            token = self.bearer_token_provider()
        if token:
            return {"Authorization": f"Bearer {token}"}
        return {}

    async def execute_tool(self, tool_name: str, args: Dict[str, Any], **metadata: Any) -> Dict[str, Any]:
        payload = {"tool_name": tool_name, "args": args, **metadata}
        headers = {"X-API-Key": self.api_key, **self._authorization_header()}
        if self.user_token:
            headers["X-User-Token"] = self.user_token
        response = await self._client.post("/v1/tool/execute", json=payload, headers=headers)
        response.raise_for_status()
        return response.json()

    async def approve(self, approval_id: str, token: str, approver: str) -> Dict[str, Any]:
        response = await self._client.post(
            f"/v1/approvals/{approval_id}/approve", params={"token": token, "approver": approver}
        )
        response.raise_for_status()
        return response.json()

    async def replay(self, trace_id: str, dry_run: bool = False) -> Dict[str, Any]:
        response = await self._client.get(f"/v1/traces/{trace_id}/replay", params={"dry_run": dry_run})
        response.raise_for_status()
        return response.json()

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()
