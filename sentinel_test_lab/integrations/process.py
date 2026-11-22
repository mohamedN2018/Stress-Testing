"""Secure subprocess execution for the optional external load tools.

Commands are always argument lists (never a shell string), run without a
console window, and the whole process tree is killed on stop/cleanup.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Callable

import psutil
import structlog

from ..engines.base import EngineContext

log = structlog.get_logger("integrations.process")

# (status code or None, latency in ms, error kind or None)
RequestEvent = tuple[int | None, float, str | None]


def kill_process_tree(pid: int, timeout_s: float = 3.0) -> None:
    """Terminate a process and all of its children; force-kill what survives."""
    try:
        parent = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return
    procs = parent.children(recursive=True) + [parent]
    for proc in procs:
        try:
            proc.terminate()
        except psutil.NoSuchProcess:
            pass
    _, alive = psutil.wait_procs(procs, timeout=timeout_s)
    for proc in alive:
        try:
            proc.kill()
        except psutil.NoSuchProcess:
            pass
    psutil.wait_procs(alive, timeout=timeout_s)


class NdjsonTail:
    """Incrementally reads complete JSON lines appended to a file."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._offset = 0
        self._partial = b""

    def read(self) -> list[dict[str, Any]]:
        try:
            with self._path.open("rb") as handle:
                handle.seek(self._offset)
                chunk = handle.read()
        except OSError:
            return []
        self._offset += len(chunk)
        data = self._partial + chunk
        lines = data.split(b"\n")
        self._partial = lines.pop()
        events: list[dict[str, Any]] = []
        for line in lines:
            if not line.strip():
                continue
            try:
                parsed = json.loads(line)
            except ValueError:
                continue
            if isinstance(parsed, dict):
                events.append(parsed)
        return events


async def run_external_tool(
    ctx: EngineContext,
    args: list[str],
    env_extra: dict[str, str],
    events_path: Path,
    handle_event: Callable[[dict[str, Any]], RequestEvent | None],
    log_path: Path,
) -> int | None:
    """Run an external load tool and feed its per-request events into the metrics.

    Each observed request consumes the run's request budget; when the budget or
    any stop condition is hit the process tree is killed. Returns the exit code
    (None if the process had to be killed).
    """
    events_path.write_bytes(b"")
    env = {**os.environ, **env_extra}
    flags = 0
    if os.name == "nt":
        flags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
    log.info("external_tool_start", tool=Path(args[0]).name, argv_len=len(args))
    with log_path.open("wb") as tool_log:
        process = subprocess.Popen(  # noqa: S603 - argument list, shell=False
            args, cwd=str(ctx.work_dir), env=env, stdin=subprocess.DEVNULL,
            stdout=tool_log, stderr=subprocess.STDOUT, shell=False, creationflags=flags,
        )
        tail = NdjsonTail(events_path)
        exit_code: int | None = None
        try:
            while True:
                finished = process.poll() is not None
                for event in tail.read():
                    result = handle_event(event)
                    if result is None:
                        continue
                    if not ctx.guard.reserve():
                        break
                    ctx.metrics.record(*result)
                if ctx.guard.exhausted:
                    ctx.guard.budget_stop()
                if ctx.guard.stopped or finished:
                    exit_code = process.returncode if finished else None
                    break
                await asyncio.sleep(0.2)
        finally:
            if process.poll() is None:
                await asyncio.to_thread(kill_process_tree, process.pid)
            ctx.metrics.set_users(0)
    log.info("external_tool_end", exit_code=exit_code)
    return exit_code
