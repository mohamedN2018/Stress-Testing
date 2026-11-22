"""Coordinates one test run: authorization, execution, monitoring, persistence."""

from __future__ import annotations

import asyncio
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable

import structlog

from ..database.repository import Repository
from ..engines.base import Engine, EngineContext
from ..engines.registry import engine_for
from ..monitoring.container_metrics import ContainerMetricsSampler
from ..monitoring.system_metrics import SystemMetricsSampler
from ..reporting.recommendations import analyze_performance, max_sustainable_tested_users
from .audit import AuditLogger
from .authorization import ScopeError, TargetError, recheck_scope
from .config import AppPaths
from .metrics_collector import MetricsCollector
from .models import (
    AuthorizedTarget,
    EngineOutcome,
    RunRecord,
    RunStatus,
    TestConfig,
    utcnow_iso,
)
from .safety_manager import STOP_SAFETY, STOP_USER, RunGuard, SafetyManager, SafetyViolation
from .secrets_store import CLOUDFLARE_TOKEN, ZAP_API_KEY, SecretStore

log = structlog.get_logger("orchestrator")

__test__ = False


@dataclass
class PreparedRun:
    config: TestConfig
    target: AuthorizedTarget
    guard: RunGuard
    metrics: MetricsCollector
    record: RunRecord
    messages: deque[str] = field(default_factory=lambda: deque(maxlen=200))
    started_monotonic: float = field(default_factory=time.monotonic)

    def emit(self, message: str) -> None:
        self.messages.append(f"[{time.strftime('%H:%M:%S')}] {message}")


class TestOrchestrator:
    __test__ = False

    STOP_GRACE_S = 1.0

    def __init__(
        self,
        repo: Repository,
        safety: SafetyManager,
        audit: AuditLogger,
        paths: AppPaths,
        secrets: SecretStore,
        engine_factory: Callable[[TestConfig], Engine] = engine_for,
    ) -> None:
        self._repo = repo
        self._safety = safety
        self._audit = audit
        self._paths = paths
        self._secrets = secrets
        self._engine_factory = engine_factory
        self._lock = threading.Lock()
        self._active: PreparedRun | None = None
        self._system = SystemMetricsSampler()
        self._container: ContainerMetricsSampler | None = None

    @property
    def active(self) -> PreparedRun | None:
        return self._active

    # ---------------------------------------------------------------- prepare
    def prepare(
        self,
        config: TestConfig,
        target_id: int | None,
        *,
        confirmed: bool,
        elevated_confirmation: str = "",
    ) -> PreparedRun:
        """Authorize a run and register it. Raises :class:`SafetyViolation` when refused."""
        target = self._repo.get_target(target_id)
        with self._lock:
            if self._active is not None:
                raise SafetyViolation("يوجد اختبار قيد التشغيل بالفعل؛ لا يُسمح بتشغيل اختبارين معاً.")
            approved = self._safety.authorize_run(
                config, target, confirmed=confirmed, elevated_confirmation=elevated_confirmation
            )
            assert target is not None
            metrics = MetricsCollector()
            guard = self._safety.create_guard(approved, metrics)
            record = self._repo.save_run(RunRecord(
                name=approved.name or approved.test_type.value,
                test_type=approved.test_type,
                target_id=target.id,
                target_url=target.base_url,
                status=RunStatus.RUNNING,
                started_at=utcnow_iso(),
                config=approved.to_dict(),
                backend=approved.backend.value,
            ))
            prepared = PreparedRun(approved, target, guard, metrics, record)
            self._active = prepared
        self._audit.record("run_started", target=target.base_url, run_id=record.id,
                           test_type=approved.test_type.value)
        return prepared

    def stop(self, prepared: PreparedRun | None = None) -> None:
        """Emergency stop: safe to call from any thread."""
        run = prepared or self._active
        if run is None:
            return
        run.guard.emergency_stop()
        self._audit.record("emergency_stop_requested", target=run.target.base_url, run_id=run.record.id)

    # ---------------------------------------------------------------- execute
    async def execute(self, prepared: PreparedRun) -> RunRecord:
        record, guard, metrics = prepared.record, prepared.guard, prepared.metrics
        outcome = EngineOutcome()
        failure = ""
        extra_details: dict[str, object] = {}
        settings = self._repo.load_settings()
        self._container = None
        if settings.monitor_container:
            self._container = ContainerMetricsSampler(
                settings.monitor_container, settings.monitor_ssh_host).start()
            where = settings.monitor_ssh_host or "هذا الجهاز"
            prepared.emit(f"مراقبة موارد الحاوية «{settings.monitor_container}» على {where}")
        sampler = asyncio.create_task(self._sampler(prepared))
        try:
            await recheck_scope(prepared.target)
            ctx = EngineContext(
                config=prepared.config,
                target=prepared.target,
                guard=guard,
                metrics=metrics,
                settings=self._repo.load_settings(),
                work_dir=self._paths.work_dir,
                emit=prepared.emit,
                secrets={
                    "zap_api_key": self._secrets.get(ZAP_API_KEY),
                    "cloudflare_token": self._secrets.get(CLOUDFLARE_TOKEN),
                },
                extra_details=extra_details,
            )
            engine = self._engine_factory(prepared.config)
            outcome = await self._run_engine(engine, ctx, guard)
        except (ScopeError, TargetError) as exc:
            failure = str(exc)
            self._audit.record("run_scope_rejected", target=prepared.target.base_url,
                               run_id=record.id, reason=failure)
        except Exception as exc:  # noqa: BLE001 - reported to the user, never swallowed
            failure = f"{type(exc).__name__}: {exc}"
            log.exception("engine_failed", run_id=record.id)
        finally:
            sampler.cancel()
            await asyncio.gather(sampler, return_exceptions=True)
            metrics.finish()
            self._tick(prepared)
            if self._container is not None:
                self._container.stop()
            outcome.details = {**extra_details, **outcome.details}
            self._finalize(prepared, outcome, failure)
            with self._lock:
                self._active = None
        return record

    async def _run_engine(self, engine: Engine, ctx: EngineContext, guard: RunGuard) -> EngineOutcome:
        task = asyncio.create_task(engine.run(ctx))
        try:
            while not task.done():
                if guard.stopped:
                    # engines wind down by themselves; force-cancel after a short grace
                    done, _ = await asyncio.wait({task}, timeout=self.STOP_GRACE_S)
                    if not done:
                        task.cancel()
                    break
                await asyncio.wait({task}, timeout=0.05)
            return await task
        except asyncio.CancelledError:
            if not task.cancelled():  # we are being cancelled from outside
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                raise
            return EngineOutcome(details={"interrupted": True})

    async def _sampler(self, prepared: PreparedRun) -> None:
        """Once per second: close a metrics interval; 4x per second: evaluate stop rules."""
        ticks = 0
        while True:
            await asyncio.sleep(0.25)
            ticks += 1
            prepared.guard.evaluate()
            if ticks % 4 == 0:
                self._tick(prepared)

    def _tick(self, prepared: PreparedRun) -> None:
        container = self._container.latest() if self._container is not None else None
        prepared.metrics.tick(self._system.sample().to_dict(),
                              {"container": container} if container else None)

    def _finalize(self, prepared: PreparedRun, outcome: EngineOutcome, failure: str) -> None:
        record, guard, config = prepared.record, prepared.guard, prepared.config
        summary = prepared.metrics.summary()
        if guard.exhausted and not guard.stopped:
            guard.budget_stop()
        if failure:
            record.status, record.stop_reason = RunStatus.FAILED, failure
        elif guard.stop_kind == STOP_USER:
            record.status, record.stop_reason = RunStatus.STOPPED, guard.stop_reason
        elif guard.stop_kind == STOP_SAFETY:
            record.status, record.stop_reason = RunStatus.AUTO_STOPPED, guard.stop_reason
        else:
            record.status, record.stop_reason = RunStatus.COMPLETED, guard.stop_reason
        summary["max_sustainable_tested_users"] = max_sustainable_tested_users(
            config.test_type, summary, outcome.details, config.thresholds
        )
        summary["request_budget"] = guard.budget
        summary["metrics_host_scope"] = (
            "target_and_generator" if prepared.target.is_local else "generator_only"
        )
        if self._container is not None:
            summary["container_monitor"] = self._container.describe()
        record.summary = summary
        record.details = outcome.details
        record.series = prepared.metrics.series
        record.findings = outcome.findings + analyze_performance(
            config.test_type, summary, record.series
        )
        record.finished_at = utcnow_iso()
        self._repo.save_run(record)
        prepared.emit(f"انتهى التشغيل: {record.status.value}")
        self._audit.record(
            "run_finished", target=prepared.target.base_url, run_id=record.id,
            status=record.status.value, stop_reason=record.stop_reason,
            total_requests=summary.get("total"), stop_latency_note=guard.stop_kind,
        )
