"""SQLite access: per-operation connections (thread-safe) and numbered migrations."""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .. import resource_path

MIGRATIONS_DIR = resource_path("database", "migrations")


class Database:
    def __init__(self, path: Path | str) -> None:
        self.path = str(path)
        self._write_lock = threading.Lock()
        # An in-memory database only lives as long as one connection: keep it open.
        self._shared: sqlite3.Connection | None = None
        if self.path == ":memory:":
            self._shared = self._open()
        self.migrate()

    def _open(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        if self.path != ":memory:":
            conn.execute("PRAGMA journal_mode = WAL")
        return conn

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Yield a connection inside a transaction; writes are serialized."""
        with self._write_lock:
            conn = self._shared or self._open()
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                if conn is not self._shared:
                    conn.close()

    def migrate(self) -> int:
        """Apply pending ``NNNN_name.sql`` files; return the schema version."""
        with self.connect() as conn:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            for script in sorted(MIGRATIONS_DIR.glob("[0-9][0-9][0-9][0-9]_*.sql")):
                number = int(script.name[:4])
                if number <= version:
                    continue
                conn.executescript(script.read_text(encoding="utf-8"))
                conn.execute(f"PRAGMA user_version = {number}")
                version = number
            return version

    def close(self) -> None:
        if self._shared is not None:
            self._shared.close()
            self._shared = None
