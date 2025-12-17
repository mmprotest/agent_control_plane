from __future__ import annotations

from typing import Any, Dict, Optional

import httpx


class AgentControlPlaneClient:
    def __init__(self, base_url: str, api_key: str, user_token: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.user_token = user_token
        self._client = httpx.AsyncClient(base_url=self.base_url)

    async def execute_tool(self, tool_name: str, args: Dict[str, Any], **metadata: Any) -> Dict[str, Any]:
        payload = {"tool_name": tool_name, "args": args, **metadata}
        headers = {"X-API-Key": self.api_key}
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
        await self._client.aclose()
