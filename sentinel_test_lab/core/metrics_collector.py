"""Thread-safe collection of real request metrics.

Engines call :meth:`MetricsCollector.record` from the worker thread; the UI
thread reads :meth:`snapshot`. Nothing here invents values: a metric that has
no samples is reported as ``None`` and rendered as "unavailable".
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from ..monitoring.performance_metrics import LatencyHistogram


@dataclass
class _Counters:
    total: int = 0
    success: int = 0
    failed: int = 0
    s2xx: int = 0
    s3xx: int = 0
    s4xx: int = 0
    s5xx: int = 0
    s429: int = 0
    transport_errors: int = 0

    def add(self, status: int | None) -> bool:
        """Count one request; return True when it is a success."""
        self.total += 1
        ok = False
        if status is None:
            self.transport_errors += 1
        elif status < 300:
            self.s2xx += 1
            ok = True
        elif status < 400:
            self.s3xx += 1
            ok = True
        elif status < 500:
            self.s4xx += 1
            if status == 429:
                self.s429 += 1
        else:
            self.s5xx += 1
        if ok:
            self.success += 1
        else:
            self.failed += 1
        return ok

    @property
    def error_rate(self) -> float | None:
        return self.failed / self.total if self.total else None


@dataclass
class PhaseStats:
    counters: _Counters = field(default_factory=_Counters)
    histogram: LatencyHistogram = field(default_factory=LatencyHistogram)
    users: int = 0
    started: float = 0.0
    ended: float | None = None

    def to_dict(self) -> dict[str, Any]:
        duration = (self.ended or time.monotonic()) - self.started if self.started else 0.0
        data: dict[str, Any] = asdict(self.counters)
        data.update(self.histogram.summary())
        data["error_rate"] = _round(self.counters.error_rate, 4)
        data["users"] = self.users
        data["duration_s"] = round(duration, 2)
        data["rps"] = round(self.counters.total / duration, 2) if duration > 0 else None
        return data


@dataclass(frozen=True)
class MetricsSnapshot:
    elapsed_s: float
    users: int
    phase: str
    total: int
    success: int
    failed: int
    s2xx: int
    s3xx: int
    s4xx: int
    s5xx: int
    s429: int
    transport_errors: int
    aborted: int
    rps: float | None
    avg_ms: float | None
    p50_ms: float | None
    p90_ms: float | None
    p95_ms: float | None
    p99_ms: float | None
    min_ms: float | None
    max_ms: float | None
    error_rate: float | None
    error_kinds: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class MetricsCollector:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._start = clock()
        self._end: float | None = None
        self._counters = _Counters()
        self._hist = LatencyHistogram()
        self._interval_counters = _Counters()
        self._interval_hist = LatencyHistogram()
        self._interval_start = self._start
        self._last_rps: float | None = None
        self._users = 0
        self._phase = ""
        self._phases: dict[str, PhaseStats] = {}
        self._recent: deque[tuple[float, bool, float, bool]] = deque()
        self._consecutive_failures = 0
        self._consecutive_server_failures = 0
        self._aborted = 0
        self._error_kinds: dict[str, int] = {}
        self.series: list[dict[str, Any]] = []

    # ------------------------------------------------------------- recording
    def record(self, status: int | None, latency_ms: float, error: str | None = None) -> None:
        now = self._clock()
        with self._lock:
            ok = self._counters.add(status)
            self._interval_counters.add(status)
            self._hist.record(latency_ms)
            self._interval_hist.record(latency_ms)
            if self._phase:
                phase = self._phases[self._phase]
                phase.counters.add(status)
                phase.histogram.record(latency_ms)
            server_fail = status is None or status >= 500
            self._recent.append((now, ok, latency_ms, server_fail))
            self._consecutive_failures = 0 if ok else self._consecutive_failures + 1
            self._consecutive_server_failures = (
                self._consecutive_server_failures + 1 if server_fail else 0
            )
            if error:
                self._error_kinds[error] = self._error_kinds.get(error, 0) + 1

    def record_aborted(self) -> None:
        """A request was already on the wire when the run stopped and was abandoned.

        It may have reached the target, so it is reported, but it has no status
        or latency and is not part of the success/failure totals.
        """
        with self._lock:
            self._aborted += 1

    def set_users(self, users: int) -> None:
        with self._lock:
            self._users = users
            if self._phase:
                phase = self._phases[self._phase]
                phase.users = max(phase.users, users)

    def set_phase(self, name: str) -> None:
        now = self._clock()
        with self._lock:
            if self._phase and self._phase in self._phases:
                self._phases[self._phase].ended = now
            self._phase = name
            if name and name not in self._phases:
                self._phases[name] = PhaseStats(started=now, users=self._users)

    def finish(self) -> None:
        now = self._clock()
        with self._lock:
            if self._end is None:
                self._end = now
            if self._phase and self._phase in self._phases:
                self._phases[self._phase].ended = now
            self._users = 0

    # --------------------------------------------------------------- reading
    @property
    def elapsed_s(self) -> float:
        return (self._end or self._clock()) - self._start

    @property
    def total(self) -> int:
        with self._lock:
            return self._counters.total

    @property
    def consecutive_failures(self) -> int:
        with self._lock:
            return self._consecutive_failures

    @property
    def consecutive_server_failures(self) -> int:
        with self._lock:
            return self._consecutive_server_failures

    def window_stats(
        self, window_s: float
    ) -> tuple[int, float | None, float | None, float | None]:
        """(samples, error rate, p95 ms, server-error rate) over the trailing window."""
        cutoff = self._clock() - window_s
        with self._lock:
            while self._recent and self._recent[0][0] < cutoff:
                self._recent.popleft()
            samples = list(self._recent)
        if not samples:
            return 0, None, None, None
        failures = sum(1 for s in samples if not s[1])
        server_failures = sum(1 for s in samples if s[3])
        latencies = sorted(s[2] for s in samples)
        p95 = latencies[min(len(latencies) - 1, int(len(latencies) * 0.95))]
        return len(samples), failures / len(samples), p95, server_failures / len(samples)

    def phase_stats(self, name: str) -> dict[str, Any] | None:
        with self._lock:
            phase = self._phases.get(name)
            return phase.to_dict() if phase else None

    def all_phases(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {name: phase.to_dict() for name, phase in self._phases.items()}

    def tick(self, system: dict[str, Any] | None = None) -> dict[str, Any]:
        """Close the current sampling interval and append it to the series."""
        now = self._clock()
        with self._lock:
            dt = max(now - self._interval_start, 1e-6)
            c, h = self._interval_counters, self._interval_hist
            self._last_rps = c.total / dt
            sample: dict[str, Any] = {
                "t": round(now - self._start, 2),
                "users": self._users,
                "phase": self._phase,
                "rps": round(self._last_rps, 2),
                "requests": c.total,
                "failed": c.failed,
                "s2xx": c.s2xx,
                "s3xx": c.s3xx,
                "s4xx": c.s4xx,
                "s5xx": c.s5xx,
                "s429": c.s429,
                "avg_ms": _round(h.mean_ms),
                "p95_ms": _round(h.percentile(95)),
                "error_rate": _round(c.error_rate, 4),
            }
            if system:
                sample["system"] = system
            self._interval_counters = _Counters()
            self._interval_hist = LatencyHistogram()
            self._interval_start = now
            if dt < 0.5 and self.series:
                # A short trailing interval (end of run) is folded into the previous
                # sample instead of being plotted as a misleading spike or drop.
                last = self.series[-1]
                merged = last["requests"] + c.total
                if c.total:
                    if last.get("avg_ms") is not None and sample["avg_ms"] is not None:
                        last["avg_ms"] = round(
                            (last["avg_ms"] * last["requests"] + sample["avg_ms"] * c.total) / merged, 2)
                        last["p95_ms"] = max(last["p95_ms"] or 0, sample["p95_ms"] or 0)
                    elif sample["avg_ms"] is not None:
                        last["avg_ms"], last["p95_ms"] = sample["avg_ms"], sample["p95_ms"]
                    for key in ("failed", "s2xx", "s3xx", "s4xx", "s5xx", "s429"):
                        last[key] += sample[key]
                    last["requests"] = merged
                    last["error_rate"] = round(last["failed"] / merged, 4)
                return last
            self.series.append(sample)
            return sample

    def snapshot(self) -> MetricsSnapshot:
        with self._lock:
            c, h = self._counters, self._hist
            elapsed = (self._end or self._clock()) - self._start
            rps = self._last_rps
            if self._end is not None:
                rps = c.total / elapsed if elapsed > 0 and c.total else None
            return MetricsSnapshot(
                elapsed_s=round(elapsed, 2),
                users=self._users,
                phase=self._phase,
                total=c.total,
                success=c.success,
                failed=c.failed,
                s2xx=c.s2xx,
                s3xx=c.s3xx,
                s4xx=c.s4xx,
                s5xx=c.s5xx,
                s429=c.s429,
                transport_errors=c.transport_errors,
                aborted=self._aborted,
                rps=_round(rps),
                avg_ms=_round(h.mean_ms),
                p50_ms=_round(h.percentile(50)),
                p90_ms=_round(h.percentile(90)),
                p95_ms=_round(h.percentile(95)),
                p99_ms=_round(h.percentile(99)),
                min_ms=_round(h.min_ms if h.count else None),
                max_ms=_round(h.max_ms if h.count else None),
                error_rate=_round(c.error_rate, 4),
                error_kinds=dict(self._error_kinds),
            )

    def summary(self) -> dict[str, Any]:
        """Final totals for persistence (overall average RPS over the whole run)."""
        snap = self.snapshot()
        data = snap.to_dict()
        elapsed = snap.elapsed_s
        data["rps"] = round(snap.total / elapsed, 2) if elapsed > 0 and snap.total else None
        data["peak_rps"] = max((s["rps"] for s in self.series), default=None)
        data["peak_users"] = max((s["users"] for s in self.series), default=snap.users)
        data.pop("users", None)
        data.pop("phase", None)
        return data


def _round(value: float | None, digits: int = 2) -> float | None:
    return None if value is None else round(value, digits)
