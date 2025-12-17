from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import DefaultDict, Deque

from acp_backend.core.config import get_settings


class RateLimiter:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.requests: DefaultDict[str, Deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.time()
        window = 60
        limit = self.settings.rate_limit_per_minute
        queue = self.requests[key]
        while queue and now - queue[0] > window:
            queue.popleft()
        if len(queue) >= limit:
            return False
        queue.append(now)
        return True
