"""Runs a locally installed OWASP ZAP as a private daemon for the application.

The daemon listens on 127.0.0.1 only, uses a random API key generated for this
session (kept in memory), its own home directory, and ``-silent`` so ZAP makes
no unsolicited requests (no update checks). It is shut down with the application.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable

import structlog

from ...core.config import Settings
from ..process import kill_process_tree
from .client import ZapClient

log = structlog.get_logger("integrations.zap")
STARTUP_TIMEOUT_S = 180.0


def find_zap(settings: Settings | None = None) -> Path | None:
    """Path of the ZAP jar of a local installation, or None."""
    candidates: list[Path] = []
    configured = getattr(settings, "zap_path", "") if settings else ""
    if configured:
        candidates.append(Path(configured))
    for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"),
                 os.environ.get("LOCALAPPDATA")):
        if base:
            candidates.append(Path(base) / "ZAP" / "Zed Attack Proxy")
    for directory in candidates:
        if directory.is_file() and directory.suffix == ".jar":
            return directory
        if directory.is_dir():
            jars = sorted(directory.glob("zap-*.jar"))
            if jars:
                return jars[-1]
    return None


def find_java() -> str | None:
    found = shutil.which("java")
    if found:
        return found
    home = os.environ.get("JAVA_HOME")
    if home and (Path(home) / "bin" / "java.exe").is_file():
        return str(Path(home) / "bin" / "java.exe")
    return None


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ZapDaemon:
    """One managed ZAP process. Thread-safe start/stop; safe to query from any thread."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._process: subprocess.Popen[bytes] | None = None
        self.url = ""
        self.api_key = ""
        self.version = ""

    @property
    def running(self) -> bool:
        process = self._process
        return process is not None and process.poll() is None and bool(self.version)

    @staticmethod
    def unavailable_reason(settings: Settings | None = None) -> str:
        """'' when a local ZAP can be started; otherwise why not."""
        if find_zap(settings) is None:
            return "OWASP ZAP غير مثبت على هذا الجهاز"
        if find_java() is None:
            return "ZAP مثبت لكن Java غير موجودة في PATH (يتطلب Java 17 أو أحدث)"
        return ""

    async def ensure_running(
        self, home_dir: Path, settings: Settings | None = None,
        should_stop: Callable[[], bool] = lambda: False,
    ) -> str:
        """Start the daemon if needed and wait until its API answers. Returns the ZAP version."""
        if self.running:
            return self.version
        reason = self.unavailable_reason(settings)
        if reason:
            raise RuntimeError(reason)
        jar, java = find_zap(settings), find_java()
        assert jar is not None and java is not None
        with self._lock:
            self._kill()
            port = _free_port()
            self.api_key = secrets.token_hex(16)
            self.url = f"http://127.0.0.1:{port}"
            home_dir.mkdir(parents=True, exist_ok=True)
            args = [
                java, "-Xmx1024m", "-jar", str(jar), "-daemon", "-silent",
                "-host", "127.0.0.1", "-port", str(port), "-dir", str(home_dir),
                "-config", f"api.key={self.api_key}",
                "-config", "api.addrs.addr.name=127.0.0.1", "-config", "api.addrs.addr.regex=false",
            ]
            flags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
            log_file = (home_dir / "zap-daemon.log").open("wb")
            self._process = subprocess.Popen(  # noqa: S603 - argument list, no shell
                args, cwd=str(jar.parent), stdin=subprocess.DEVNULL, stdout=log_file,
                stderr=subprocess.STDOUT, shell=False, creationflags=flags)
            log_file.close()
            log.info("zap_daemon_starting", port=port, jar=jar.name)
        client = ZapClient(self.url, self.api_key, timeout_s=5)
        deadline = time.monotonic() + STARTUP_TIMEOUT_S
        while time.monotonic() < deadline:
            if should_stop():
                self.stop()
                raise RuntimeError("أُلغي تشغيل ZAP")
            if self._process is None or self._process.poll() is not None:
                raise RuntimeError(f"توقف ZAP أثناء الإقلاع. راجع السجل: {home_dir / 'zap-daemon.log'}")
            version = await client.version()
            if version:
                self.version = version
                log.info("zap_daemon_ready", version=version)
                return version
            await asyncio.sleep(1.0)
        self.stop()
        raise RuntimeError(f"لم يستجب ZAP خلال {STARTUP_TIMEOUT_S:.0f} ثانية")

    def _kill(self) -> None:
        process, self._process = self._process, None
        self.version = ""
        if process is not None and process.poll() is None:
            kill_process_tree(process.pid)

    def stop(self) -> None:
        with self._lock:
            self._kill()
            self.url = self.api_key = ""


_daemon = ZapDaemon()


def local_daemon() -> ZapDaemon:
    """The application's single managed ZAP daemon."""
    return _daemon
