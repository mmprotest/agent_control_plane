from __future__ import annotations

from typing import Any, Dict
from urllib.parse import urlparse

import httpx


class HttpToolConnector:
    async def execute(
        self,
        endpoint: str,
        args: Dict[str, Any],
        allowed_domains: list[str] | None = None,
        denied_domains: list[str] | None = None,
    ) -> Dict[str, Any]:
        parsed = urlparse(endpoint)
        hostname = parsed.hostname.lower() if parsed.hostname else None
        allow_list = [host.lower() for host in (allowed_domains or [])]
        deny_list = [host.lower() for host in (denied_domains or [])]
        if hostname and hostname in deny_list:
            raise ValueError("domain_denied")
        if hostname and allow_list and hostname not in allow_list:
            raise ValueError("domain_not_allowed")
        async with httpx.AsyncClient() as client:
            response = await client.post(endpoint, json=args, timeout=10)
            response.raise_for_status()
            return response.json()
