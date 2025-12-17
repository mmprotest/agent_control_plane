from __future__ import annotations

from typing import Any, Dict
from urllib.parse import urlparse

import httpx


class HttpToolConnector:
    async def execute(self, endpoint: str, args: Dict[str, Any], allowed_domains: list[str]) -> Dict[str, Any]:
        parsed = urlparse(endpoint)
        if parsed.hostname and allowed_domains and parsed.hostname not in allowed_domains:
            raise ValueError("domain_not_allowed")
        async with httpx.AsyncClient() as client:
            response = await client.post(endpoint, json=args, timeout=10)
            response.raise_for_status()
            return response.json()
