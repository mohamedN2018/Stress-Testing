"""Resource usage of the Docker container that serves the site under test.

Reads ``docker stats`` for one container, either on this machine or on your
own server through the system ``ssh`` client (key-based, non-interactive).
Read-only: nothing is started, stopped or changed on the server.
"""

from __future__ import annotations

import json
import re
import subprocess
import threading
import time
from typing import Any

CONTAINER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
SSH_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,254}$")
UNITS = {"b": 1, "kb": 1e3, "mb": 1e6, "gb": 1e9, "tb": 1e12,
         "kib": 1024, "mib": 1024 ** 2, "gib": 1024 ** 3, "tib": 1024 ** 4}
SIZE = re.compile(r"^\s*([\d.]+)\s*([A-Za-z]+)\s*$")
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class ContainerMetricsError(Exception):
    pass


def parse_size(text: str) -> float | None:
    """'12.5MiB' -> bytes; None when the text is not a size."""
    match = SIZE.match(text or "")
    if not match or match.group(2).lower() not in UNITS:
        return None
    try:
        return float(match.group(1)) * UNITS[match.group(2).lower()]
    except ValueError:
        return None


def parse_stats_line(line: str) -> dict[str, Any] | None:
    """One line of ``docker stats --format '{{json .}}'`` -> numeric sample."""
    try:
        raw = json.loads(line)
    except (ValueError, TypeError):
        return None
    if not isinstance(raw, dict):
        return None

    def percent(key: str) -> float | None:
        try:
            return round(float(str(raw.get(key, "")).rstrip("%")), 2)
        except ValueError:
            return None

    def pair(key: str) -> tuple[float | None, float | None]:
        first, _, second = str(raw.get(key, "")).partition("/")
        return parse_size(first), parse_size(second)

    used, limit = pair("MemUsage")
    rx, tx = pair("NetIO")
    try:
        pids: int | None = int(raw.get("PIDs", ""))
    except (ValueError, TypeError):
        pids = None
    sample = {
        "cpu_percent": percent("CPUPerc"),
        "mem_percent": percent("MemPerc"),
        "mem_used_mb": round(used / 1_048_576, 1) if used is not None else None,
        "mem_limit_mb": round(limit / 1_048_576, 1) if limit is not None else None,
        "net_rx_bytes": rx, "net_tx_bytes": tx, "pids": pids,
    }
    return sample if sample["cpu_percent"] is not None or sample["mem_used_mb"] is not None else None


def _command(args: list[str], ssh_host: str) -> list[str]:
    if ssh_host:
        if not SSH_HOST.match(ssh_host):
            raise ContainerMetricsError("اسم خادم SSH غير صالح.")
        return ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=6", ssh_host, "docker", *args]
    return ["docker", *args]


def _run(args: list[str], ssh_host: str, timeout: float) -> str:
    try:
        done = subprocess.run(_command(args, ssh_host), capture_output=True, text=True, timeout=timeout,
                              stdin=subprocess.DEVNULL, creationflags=NO_WINDOW,
                              encoding="utf-8", errors="replace")
    except FileNotFoundError as exc:
        raise ContainerMetricsError("الأمر ssh غير موجود" if ssh_host else "Docker غير مثبت على هذا الجهاز") from exc
    except subprocess.TimeoutExpired as exc:
        raise ContainerMetricsError("انتهت المهلة دون رد") from exc
    if done.returncode != 0:
        message = (done.stderr or done.stdout).strip().splitlines()
        raise ContainerMetricsError(message[-1][:200] if message else f"فشل الأمر ({done.returncode})")
    return done.stdout


def list_containers(ssh_host: str = "", timeout: float = 10.0) -> list[str]:
    """Names of the running containers. Raises ContainerMetricsError when unavailable."""
    names = [n.strip() for n in _run(["ps", "--format", "{{.Names}}"], ssh_host, timeout).splitlines()]
    return sorted(n for n in names if CONTAINER_NAME.match(n))


def read_stats(container: str, ssh_host: str = "", timeout: float = 12.0) -> dict[str, Any]:
    if not CONTAINER_NAME.match(container):
        raise ContainerMetricsError("اسم الحاوية غير صالح.")
    out = _run(["stats", "--no-stream", "--format", "{{json .}}", container], ssh_host, timeout)
    for line in out.splitlines():
        sample = parse_stats_line(line.strip())
        if sample:
            return sample
    raise ContainerMetricsError("لم يُرجع docker stats أي بيانات")


class ContainerMetricsSampler:
    """Polls ``docker stats`` on a background thread; ``latest()`` never blocks."""

    def __init__(self, container: str, ssh_host: str = "", interval_s: float = 1.0) -> None:
        self.container, self.ssh_host = container, ssh_host
        self._interval = interval_s
        self._latest: dict[str, Any] | None = None
        self._latest_at = 0.0
        self.error = ""
        self.samples = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="container-metrics", daemon=True)

    def start(self) -> "ContainerMetricsSampler":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()

    def latest(self, max_age_s: float = 8.0) -> dict[str, Any] | None:
        """Most recent sample, or None if there is none or it is stale."""
        if self._latest is None or time.monotonic() - self._latest_at > max_age_s:
            return None
        return dict(self._latest)

    def describe(self) -> dict[str, Any]:
        return {"container": self.container, "host": self.ssh_host or "هذا الجهاز",
                "samples": self.samples, "error": self.error}

    def _loop(self) -> None:
        failures = 0
        while not self._stop.is_set():
            try:
                self._latest = read_stats(self.container, self.ssh_host)
                self._latest_at = time.monotonic()
                self.samples += 1
                self.error, failures = "", 0
            except ContainerMetricsError as exc:
                self.error = str(exc)
                failures += 1
                if failures >= 3:  # do not keep hammering a server that refuses
                    return
            self._stop.wait(self._interval)
