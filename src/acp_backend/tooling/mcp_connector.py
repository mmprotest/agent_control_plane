from __future__ import annotations

from typing import Any, Callable, Dict, List

import httpx


class McpHttpConnector:
    def __init__(self, client_factory: Callable[[str], httpx.AsyncClient] | None = None):
        self._client_factory = client_factory

    def _client(self, base_url: str) -> httpx.AsyncClient:
        if self._client_factory:
            return self._client_factory(base_url)
        return httpx.AsyncClient(base_url=base_url, timeout=10)

    async def discover_tools(self, base_url: str) -> List[Dict[str, Any]]:
        async with self._client(base_url) as client:
            response = await client.get("/mcp/tools")
            response.raise_for_status()
            data = response.json()
            return data.get("tools", [])

    async def execute(self, base_url: str, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        async with self._client(base_url) as client:
            response = await client.post(f"/mcp/tools/{tool_name}", json=args)
            response.raise_for_status()
            return response.json()
