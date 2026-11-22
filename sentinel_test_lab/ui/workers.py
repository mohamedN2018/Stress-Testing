"""Background execution: nothing that touches the network runs on the UI thread."""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable

import structlog
from PySide6.QtCore import QObject, QThread, Signal

log = structlog.get_logger("ui.worker")
_running: set["AsyncWorker"] = set()


class AsyncWorker(QThread):
    """Runs one coroutine on its own event loop in a worker thread."""

    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(self, factory: Callable[[], Awaitable[Any]], parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._factory = factory

    def run(self) -> None:  # executed in the worker thread
        try:
            result = asyncio.run(self._factory())
        except Exception as exc:  # noqa: BLE001 - reported to the UI
            log.exception("background_task_failed")
            self.failed.emit(f"{type(exc).__name__}: {exc}")
            return
        self.succeeded.emit(result)


def run_async(
    factory: Callable[[], Awaitable[Any]],
    on_success: Callable[[Any], None],
    on_failure: Callable[[str], None] | None = None,
) -> AsyncWorker:
    """Start a background coroutine; callbacks are delivered on the UI thread."""
    worker = AsyncWorker(factory)
    _running.add(worker)
    worker.succeeded.connect(on_success)
    if on_failure is not None:
        worker.failed.connect(on_failure)
    worker.finished.connect(lambda: _running.discard(worker))
    worker.start()
    return worker


def wait_for_workers(timeout_ms: int = 5000) -> None:
    for worker in list(_running):
        worker.wait(timeout_ms)
