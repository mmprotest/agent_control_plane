from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Callable, DefaultDict, Deque

from acp_backend.core.config import get_settings


class RateLimiter:
    def __init__(self, *, time_fn: Callable[[], float] | None = None) -> None:
        self.settings = get_settings()
        self.requests: DefaultDict[str, Deque[float]] = defaultdict(deque)
        self.time_fn = time_fn or time.time

    def allow(self, key: str, limit: int | None = None, window_seconds: int = 60) -> bool:
        now = self.time_fn()
        window = window_seconds
        max_calls = limit or self.settings.rate_limit_per_minute
        queue = self.requests[key]
        while queue and now - queue[0] > window:
            queue.popleft()
        if len(queue) >= max_calls:
            return False
        queue.append(now)
        return True
