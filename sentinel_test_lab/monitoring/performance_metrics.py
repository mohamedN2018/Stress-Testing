"""Latency histogram with bounded memory and ~1% percentile precision."""

from __future__ import annotations

import math

_GROWTH = 1.02
_LOG_GROWTH = math.log(_GROWTH)
_MIN_MS = 0.01


class LatencyHistogram:
    """Log-bucketed histogram. Not thread-safe; callers hold their own lock."""

    __slots__ = ("_buckets", "count", "total_ms", "min_ms", "max_ms")

    def __init__(self) -> None:
        self._buckets: dict[int, int] = {}
        self.count = 0
        self.total_ms = 0.0
        self.min_ms = math.inf
        self.max_ms = 0.0

    def record(self, value_ms: float) -> None:
        value_ms = max(value_ms, _MIN_MS)
        index = int(math.log(value_ms / _MIN_MS) / _LOG_GROWTH)
        self._buckets[index] = self._buckets.get(index, 0) + 1
        self.count += 1
        self.total_ms += value_ms
        self.min_ms = min(self.min_ms, value_ms)
        self.max_ms = max(self.max_ms, value_ms)

    @property
    def mean_ms(self) -> float | None:
        return self.total_ms / self.count if self.count else None

    def percentile(self, pct: float) -> float | None:
        """Return the latency below which ``pct`` percent of samples fall."""
        if not self.count:
            return None
        rank = max(1, math.ceil(self.count * pct / 100.0))
        seen = 0
        for index in sorted(self._buckets):
            seen += self._buckets[index]
            if seen >= rank:
                upper = _MIN_MS * (_GROWTH ** (index + 1))
                return min(max(upper, self.min_ms), self.max_ms)
        return self.max_ms

    def merge(self, other: "LatencyHistogram") -> None:
        for index, n in other._buckets.items():
            self._buckets[index] = self._buckets.get(index, 0) + n
        self.count += other.count
        self.total_ms += other.total_ms
        self.min_ms = min(self.min_ms, other.min_ms)
        self.max_ms = max(self.max_ms, other.max_ms)

    def summary(self) -> dict[str, float | None]:
        return {
            "count": self.count,
            "avg_ms": _r(self.mean_ms),
            "min_ms": _r(self.min_ms if self.count else None),
            "max_ms": _r(self.max_ms if self.count else None),
            "p50_ms": _r(self.percentile(50)),
            "p90_ms": _r(self.percentile(90)),
            "p95_ms": _r(self.percentile(95)),
            "p99_ms": _r(self.percentile(99)),
        }


def _r(value: float | None) -> float | None:
    return None if value is None else round(value, 2)
