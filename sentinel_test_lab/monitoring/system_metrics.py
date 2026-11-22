"""Host resource metrics for the machine running Sentinel Test Lab.

These describe the *load generator* host. They describe the target only when
the target runs on this same machine (localhost testing). Remote host and
database metrics are not collected and are reported as unavailable.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from typing import Any

import psutil


@dataclass(frozen=True)
class SystemSample:
    cpu_percent: float | None
    ram_percent: float | None
    ram_used_mb: float | None
    disk_percent: float | None
    net_sent_kbps: float | None
    net_recv_kbps: float | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SystemMetricsSampler:
    """Samples CPU, memory, disk and network throughput via psutil."""

    def __init__(self) -> None:
        self._last_net: tuple[float, int, int] | None = None
        try:
            psutil.cpu_percent(interval=None)  # prime the counter
        except Exception:  # pragma: no cover - platform specific
            pass

    def sample(self) -> SystemSample:
        cpu = _safe(lambda: psutil.cpu_percent(interval=None))
        mem = _safe(psutil.virtual_memory)
        disk = _safe(lambda: psutil.disk_usage(_root_path()))
        sent_kbps = recv_kbps = None
        net = _safe(psutil.net_io_counters)
        now = time.monotonic()
        if net is not None:
            if self._last_net is not None:
                last_t, last_sent, last_recv = self._last_net
                dt = now - last_t
                if dt > 0:
                    sent_kbps = round((net.bytes_sent - last_sent) * 8 / 1000 / dt, 1)
                    recv_kbps = round((net.bytes_recv - last_recv) * 8 / 1000 / dt, 1)
            self._last_net = (now, net.bytes_sent, net.bytes_recv)
        return SystemSample(
            cpu_percent=cpu,
            ram_percent=mem.percent if mem else None,
            ram_used_mb=round(mem.used / 1_048_576, 1) if mem else None,
            disk_percent=disk.percent if disk else None,
            net_sent_kbps=sent_kbps,
            net_recv_kbps=recv_kbps,
        )


def _root_path() -> str:
    import os

    return os.environ.get("SystemDrive", "C:") + "\\" if os.name == "nt" else "/"


def _safe(func):  # type: ignore[no-untyped-def]
    try:
        return func()
    except Exception:
        return None
