"""Persistence for targets, runs, audit entries and settings."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from ..core.config import Settings
from ..core.models import AuthorizedTarget, Environment, Finding, RunRecord, RunStatus, TestType
from .db import Database


def _dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


class Repository:
    def __init__(self, db: Database) -> None:
        self._db = db

    # ---------------------------------------------------------------- targets
    @staticmethod
    def _target(row: sqlite3.Row) -> AuthorizedTarget:
        return AuthorizedTarget(
            id=row["id"],
            name=row["name"],
            base_url=row["base_url"],
            scheme=row["scheme"],
            host=row["host"],
            port=row["port"],
            environment=Environment(row["environment"]),
            description=row["description"],
            authorization_statement=row["authorization_statement"],
            authorized_at=row["authorized_at"],
            allowed_paths=json.loads(row["allowed_paths"]),
            allowed_methods=json.loads(row["allowed_methods"]),
            pinned_ips=json.loads(row["pinned_ips"]),
            allow_private=bool(row["allow_private"]),
            network_class=row["network_class"],
            ownership_verified=bool(row["ownership_verified"]),
            verify_token=row["verify_token"],
            verify_tls=bool(row["verify_tls"]),
        )

    def save_target(self, target: AuthorizedTarget) -> AuthorizedTarget:
        values = (
            target.name, target.base_url, target.scheme, target.host, target.port,
            target.environment.value, target.description, target.authorization_statement,
            target.authorized_at, _dumps(target.allowed_paths), _dumps(target.allowed_methods),
            _dumps(target.pinned_ips), int(target.allow_private), target.network_class,
            int(target.ownership_verified), target.verify_token, int(target.verify_tls),
        )
        columns = (
            "name, base_url, scheme, host, port, environment, description, "
            "authorization_statement, authorized_at, allowed_paths, allowed_methods, pinned_ips, "
            "allow_private, network_class, ownership_verified, verify_token, verify_tls"
        )
        with self._db.connect() as conn:
            if target.id is None:
                existing = conn.execute(
                    "SELECT id, verify_token, ownership_verified FROM targets WHERE base_url = ?",
                    (target.base_url,),
                ).fetchone()
                if existing:
                    # Re-authorizing a known target keeps its ownership proof.
                    target.id = existing["id"]
                    target.verify_token = existing["verify_token"]
                    target.ownership_verified = bool(existing["ownership_verified"])
                    values = (*values[:14], int(target.ownership_verified), target.verify_token, values[16])
            if target.id is None:
                cur = conn.execute(
                    f"INSERT INTO targets ({columns}) VALUES ({', '.join('?' * 17)})", values
                )
                target.id = cur.lastrowid
            else:
                assignments = ", ".join(f"{c.strip()} = ?" for c in columns.split(","))
                conn.execute(f"UPDATE targets SET {assignments} WHERE id = ?", (*values, target.id))
        return target

    def get_target(self, target_id: int | None) -> AuthorizedTarget | None:
        if target_id is None:
            return None
        with self._db.connect() as conn:
            row = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
        return self._target(row) if row else None

    def list_targets(self) -> list[AuthorizedTarget]:
        with self._db.connect() as conn:
            rows = conn.execute("SELECT * FROM targets ORDER BY name COLLATE NOCASE").fetchall()
        return [self._target(r) for r in rows]

    def delete_target(self, target_id: int) -> None:
        with self._db.connect() as conn:
            conn.execute("DELETE FROM targets WHERE id = ?", (target_id,))

    # ------------------------------------------------------------------- runs
    @staticmethod
    def _run(row: sqlite3.Row) -> RunRecord:
        return RunRecord(
            id=row["id"],
            name=row["name"],
            test_type=TestType(row["test_type"]),
            target_id=row["target_id"],
            target_url=row["target_url"],
            status=RunStatus(row["status"]),
            backend=row["backend"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            stop_reason=row["stop_reason"],
            config=json.loads(row["config"]),
            summary=json.loads(row["summary"]),
            details=json.loads(row["details"]),
            series=json.loads(row["series"]),
            findings=[Finding.from_dict(f) for f in json.loads(row["findings"])],
        )

    def save_run(self, run: RunRecord) -> RunRecord:
        values = (
            run.name, run.test_type.value, run.target_id, run.target_url, run.status.value,
            run.backend, run.started_at, run.finished_at, run.stop_reason, _dumps(run.config),
            _dumps(run.summary), _dumps(run.details), _dumps(run.series),
            _dumps([f.to_dict() for f in run.findings]),
        )
        columns = (
            "name, test_type, target_id, target_url, status, backend, started_at, finished_at, "
            "stop_reason, config, summary, details, series, findings"
        )
        with self._db.connect() as conn:
            if run.id is None:
                cur = conn.execute(
                    f"INSERT INTO runs ({columns}) VALUES ({', '.join('?' * 14)})", values
                )
                run.id = cur.lastrowid
            else:
                assignments = ", ".join(f"{c.strip()} = ?" for c in columns.split(","))
                conn.execute(f"UPDATE runs SET {assignments} WHERE id = ?", (*values, run.id))
        return run

    def get_run(self, run_id: int) -> RunRecord | None:
        with self._db.connect() as conn:
            row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        return self._run(row) if row else None

    def list_runs(
        self,
        *,
        search: str = "",
        test_type: str = "",
        status: str = "",
        limit: int = 500,
    ) -> list[RunRecord]:
        clauses, params = [], []
        if search.strip():
            clauses.append("(name LIKE ? OR target_url LIKE ?)")
            like = f"%{search.strip()}%"
            params += [like, like]
        if test_type:
            clauses.append("test_type = ?")
            params.append(test_type)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._db.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM runs {where} ORDER BY started_at DESC, id DESC LIMIT ?",
                (*params, limit),
            ).fetchall()
        return [self._run(r) for r in rows]

    def delete_run(self, run_id: int) -> None:
        with self._db.connect() as conn:
            conn.execute("DELETE FROM runs WHERE id = ?", (run_id,))

    def mark_interrupted_runs(self) -> int:
        """Runs left as 'running' by a crash are closed as failed on startup."""
        with self._db.connect() as conn:
            cur = conn.execute(
                "UPDATE runs SET status = ?, stop_reason = ? WHERE status = ?",
                (RunStatus.FAILED.value, "أُغلق التطبيق أثناء التشغيل", RunStatus.RUNNING.value),
            )
            return cur.rowcount

    def counts(self) -> dict[str, int]:
        with self._db.connect() as conn:
            targets = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
            runs = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        return {"targets": targets, "runs": runs}

    # ------------------------------------------------------------------ audit
    def add_audit(self, ts: str, event: str, target: str, run_id: int | None, data: dict[str, Any]) -> None:
        with self._db.connect() as conn:
            conn.execute(
                "INSERT INTO audit (ts, event, target, run_id, data) VALUES (?, ?, ?, ?, ?)",
                (ts, event, target, run_id, _dumps(data)),
            )

    def list_audit(self, limit: int = 300) -> list[dict[str, Any]]:
        with self._db.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [
            {"id": r["id"], "ts": r["ts"], "event": r["event"], "target": r["target"],
             "run_id": r["run_id"], "data": json.loads(r["data"])}
            for r in rows
        ]

    # --------------------------------------------------------------- settings
    def load_settings(self) -> Settings:
        with self._db.connect() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key = 'app'").fetchone()
        return Settings.from_dict(json.loads(row["value"])) if row else Settings()

    def save_settings(self, settings: Settings) -> None:
        with self._db.connect() as conn:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES ('app', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (_dumps(settings.to_dict()),),
            )
