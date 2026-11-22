"""Global request-rate limiter shared by every virtual user of a run."""

from __future__ import annotations

import asyncio
import time
from typing import Callable


class RateLimiter:
    """Evenly spaces requests so the rate never exceeds ``rate_per_s``.

    Each caller reserves the next free time slot; slots are ``1/rate`` apart,
    so there is no burst allowance at all.
    """

    def __init__(self, rate_per_s: float, clock: Callable[[], float] = time.monotonic) -> None:
        if rate_per_s <= 0:
            raise ValueError("rate_per_s must be positive (unlimited rates are not allowed)")
        self.rate_per_s = rate_per_s
        self._interval = 1.0 / rate_per_s
        self._clock = clock
        self._next_slot = clock()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = self._clock()
            slot = max(now, self._next_slot)
            self._next_slot = slot + self._interval
        delay = slot - self._clock()
        if delay > 0:
            await asyncio.sleep(delay)
