"""Append-only audit trail: every authorization, start, stop and rejection."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Protocol

import structlog

from .models import utcnow_iso

log = structlog.get_logger("audit")


class AuditSink(Protocol):
    def add_audit(self, ts: str, event: str, target: str, run_id: int | None, data: dict[str, Any]) -> None: ...


class AuditLogger:
    """Writes each event to a JSONL file and (when given) to the database."""

    def __init__(self, file_path: Path | None = None, sink: AuditSink | None = None) -> None:
        self._file_path = file_path
        self._sink = sink
        self._lock = threading.Lock()

    def record(self, event: str, *, target: str = "", run_id: int | None = None, **data: Any) -> None:
        ts = utcnow_iso()
        entry = {"ts": ts, "event": event, "target": target, "run_id": run_id, **data}
        log.info(event, target=target, run_id=run_id, **data)
        with self._lock:
            if self._file_path is not None:
                try:
                    self._file_path.parent.mkdir(parents=True, exist_ok=True)
                    with self._file_path.open("a", encoding="utf-8") as handle:
                        handle.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
                except OSError as exc:  # never let auditing crash a test run
                    log.error("audit_file_write_failed", error=str(exc))
            if self._sink is not None:
                try:
                    self._sink.add_audit(ts, event, target, run_id, data)
                except Exception as exc:  # noqa: BLE001
                    log.error("audit_db_write_failed", error=str(exc))
