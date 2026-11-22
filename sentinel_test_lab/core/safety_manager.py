"""Safety engine: the single gate every test run must pass, plus the run-time guard.

* :class:`SafetyManager` decides *before* a run whether a configuration is
  allowed for a target (scope, limits, confirmations) and audits the decision.
* :class:`RunGuard` enforces the limits *during* a run (rate, request budget,
  deadline, automatic stop thresholds, emergency stop).
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import replace
from typing import Callable

from .audit import AuditLogger
from .authorization import ScopeError, ensure_request_in_scope
from .config import (
    ABSOLUTE_LIMITS,
    ACTIVE_SCAN_MAX_DURATION_S,
    BRUTE_FORCE_MAX_ATTEMPTS,
    BRUTE_FORCE_MIN_INTERVAL_S,
    DEFAULT_LIMITS,
    FLOOD_MAX_DURATION_S,
    FLOOD_MAX_RPS,
    SafetyLimits,
    Settings,
)
from .metrics_collector import MetricsCollector
from .models import AuthorizedTarget, Backend, TestConfig, TestType
from .rate_limiter import RateLimiter

# Modules that are only allowed against trusted targets (ownership verified or loopback).
TRUSTED_ONLY_TYPES = {TestType.FLOOD, TestType.BRUTE_FORCE}
# Modules whose expected responses include 4xx (401/429): only server-side
# failures count as instability for the automatic stop.
SERVER_ERROR_GUARD_TYPES = {
    TestType.FLOOD,
    TestType.BRUTE_FORCE,
    TestType.SECURITY,
    TestType.DDOS_POSTURE,
}
LOAD_TYPES = {TestType.LOAD, TestType.STRESS, TestType.SPIKE, TestType.FLOOD}

STOP_USER = "user"
STOP_SAFETY = "safety"
STOP_LIMIT = "limit"


class SafetyViolation(PermissionError):
    """A run was rejected by the safety engine."""


class SafetyManager:
    def __init__(self, settings_provider: Callable[[], Settings], audit: AuditLogger) -> None:
        self._settings_provider = settings_provider
        self._audit = audit

    # ----------------------------------------------------------------- limits
    def effective_limits(self, target: AuthorizedTarget | None) -> SafetyLimits:
        """Limits available to this target right now."""
        settings = self._settings_provider()
        if target is not None and target.is_trusted and settings.elevated_enabled:
            return settings.elevated_limits()
        return DEFAULT_LIMITS

    @staticmethod
    def exceeds_defaults(config: TestConfig) -> bool:
        return (
            peak_users(config) > DEFAULT_LIMITS.max_users
            or config.duration_s > DEFAULT_LIMITS.max_duration_s
            or config.rate_limit_rps > DEFAULT_LIMITS.max_rps
            or config.request_budget > DEFAULT_LIMITS.max_request_budget
        )

    # ------------------------------------------------------------ authorizing
    def authorize_run(
        self,
        config: TestConfig,
        target: AuthorizedTarget | None,
        *,
        confirmed: bool,
        elevated_confirmation: str = "",
    ) -> TestConfig:
        """Return the configuration to execute, or raise :class:`SafetyViolation`."""
        try:
            approved = self._authorize(config, target, confirmed, elevated_confirmation)
        except SafetyViolation as exc:
            self._audit.record(
                "run_rejected",
                target=target.base_url if target else "",
                test_type=config.test_type.value,
                reason=str(exc),
            )
            raise
        self._audit.record(
            "run_authorized",
            target=target.base_url if target else "",
            test_type=config.test_type.value,
            users=peak_users(approved),
            duration_s=approved.duration_s,
            rate_limit_rps=approved.rate_limit_rps,
            request_budget=approved.request_budget,
            elevated=self.exceeds_defaults(approved),
        )
        return approved

    def preview(self, config: TestConfig, target: AuthorizedTarget | None) -> str:
        """Why this configuration would be refused ('' when it is acceptable).

        Used for live form validation: nothing is audited and nothing runs.
        Confirmations are assumed given; they are still required to start.
        """
        try:
            self._authorize(config, target, True, target.host if target else "")
        except SafetyViolation as exc:
            return str(exc)
        return ""

    def _authorize(
        self,
        config: TestConfig,
        target: AuthorizedTarget | None,
        confirmed: bool,
        elevated_confirmation: str,
    ) -> TestConfig:
        if target is None or target.id is None:
            raise SafetyViolation("الهدف غير موجود في قائمة الأهداف المصرّح بها.")
        if not confirmed:
            raise SafetyViolation("يجب تأكيد التصريح قبل تشغيل أي اختبار.")
        if target.network_class != "public" and not target.allow_private:
            raise SafetyViolation("الهدف خاص/محلي بدون تصريح صريح بذلك.")

        limits = self.effective_limits(target)
        users = peak_users(config)

        for name, value in (
            ("عدد المستخدمين", users),
            ("المدة", config.duration_s),
            ("معدل الطلبات", config.rate_limit_rps),
        ):
            if not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                raise SafetyViolation(f"{name} يجب أن يكون رقماً موجباً ومحدوداً (لا يوجد وضع غير محدود).")
        if config.interval_s < 0 or config.timeout_s <= 0 or config.timeout_s > 60:
            raise SafetyViolation("قيم الفاصل الزمني أو المهلة غير صالحة.")
        if config.requests_per_user < 0 or config.request_budget < 0:
            raise SafetyViolation("قيم الطلبات لا يمكن أن تكون سالبة.")

        if config.test_type in TRUSTED_ONLY_TYPES and not target.is_trusted:
            raise SafetyViolation(
                "هذا النوع من الاختبارات متاح فقط لهدف محلي (loopback) أو لهدف تم التحقق من ملكيته."
            )
        if config.extra.get("active_scan"):
            if not target.is_trusted:
                raise SafetyViolation("الفحص النشط (Active Scan) يتطلب هدفاً تم التحقق من ملكيته.")
            if not config.extra.get("active_scan_confirmed"):
                raise SafetyViolation("الفحص النشط يتطلب تأكيداً صريحاً منفصلاً.")
            # Measured against real ZAP: active scan rules probe host-level paths and send POST
            # requests regardless of the URL they were given, so the whole host must be in scope.
            if "/" not in target.allowed_paths:
                raise SafetyViolation(
                    "الفحص النشط يرسل طلبات إلى مسارات على مستوى الموقع كله؛ "
                    "يتطلب هدفاً نطاقه «كل صفحات الموقع».")
            if "POST" not in target.allowed_methods:
                raise SafetyViolation(
                    "الفحص النشط يرسل طلبات POST؛ أضف POST إلى الطرق المسموحة للهدف أولاً.")
            if config.duration_s > ACTIVE_SCAN_MAX_DURATION_S:
                raise SafetyViolation(f"أقصى مدة للفحص النشط {ACTIVE_SCAN_MAX_DURATION_S} ثانية.")

        if users > limits.max_users:
            raise SafetyViolation(self._limit_msg("عدد المستخدمين", users, limits.max_users, target))
        if config.duration_s > limits.max_duration_s:
            raise SafetyViolation(
                self._limit_msg("المدة (ث)", config.duration_s, limits.max_duration_s, target)
            )
        if config.rate_limit_rps > limits.max_rps:
            raise SafetyViolation(
                self._limit_msg("معدل الطلبات/ث", config.rate_limit_rps, limits.max_rps, target)
            )
        if config.request_budget > limits.max_request_budget:
            raise SafetyViolation(
                self._limit_msg("ميزانية الطلبات", config.request_budget, limits.max_request_budget, target)
            )
        # Defence in depth: the compiled ceilings hold even if limits were tampered with.
        if (
            users > ABSOLUTE_LIMITS.max_users
            or config.duration_s > ABSOLUTE_LIMITS.max_duration_s
            or config.rate_limit_rps > ABSOLUTE_LIMITS.max_rps
        ):
            raise SafetyViolation("القيم المطلوبة تتجاوز السقف المطلق للتطبيق.")

        if config.test_type == TestType.FLOOD:
            if config.duration_s > FLOOD_MAX_DURATION_S or config.rate_limit_rps > FLOOD_MAX_RPS:
                raise SafetyViolation(
                    f"تقييم Flood محدود بـ {FLOOD_MAX_DURATION_S} ثانية و {FLOOD_MAX_RPS:g} طلب/ث كحد أقصى."
                )
        if config.test_type == TestType.BRUTE_FORCE:
            attempts = int(config.extra.get("attempts", 0))
            if not 1 <= attempts <= BRUTE_FORCE_MAX_ATTEMPTS:
                raise SafetyViolation(
                    f"عدد محاولات تقييم Brute Force يجب أن يكون بين 1 و {BRUTE_FORCE_MAX_ATTEMPTS}."
                )
            if config.interval_s < BRUTE_FORCE_MIN_INTERVAL_S:
                raise SafetyViolation(
                    f"أقل فاصل بين المحاولات {BRUTE_FORCE_MIN_INTERVAL_S} ثانية."
                )
            if not str(config.extra.get("test_username", "")).strip():
                raise SafetyViolation("حدّد اسم حساب الاختبار المخصص (لا تستخدم حسابات مستخدمين حقيقيين).")
            if not config.extra.get("test_account_confirmed"):
                raise SafetyViolation("يجب تأكيد أن الحساب المستخدم حساب اختبار مخصص لهذا الغرض.")

        if config.backend != Backend.INTERNAL and config.test_type != TestType.LOAD:
            raise SafetyViolation("محركات Locust و k6 مدعومة لاختبار الحمل فقط.")

        self._check_scope(config, target)

        if self.exceeds_defaults(config) and elevated_confirmation.strip().lower() != target.host.lower():
            raise SafetyViolation(
                "الإعدادات تتجاوز الحدود الافتراضية الآمنة؛ اكتب اسم المضيف للتأكيد الصريح."
            )

        budget = config.request_budget or min(
            limits.max_request_budget, math.ceil(config.rate_limit_rps * config.duration_s) + 1
        )
        return replace(config, request_budget=budget)

    @staticmethod
    def _check_scope(config: TestConfig, target: AuthorizedTarget) -> None:
        if config.test_type not in LOAD_TYPES:
            return  # assessment engines validate each request through ScopedHttp
        if not config.paths:
            raise SafetyViolation("حدّد مساراً واحداً على الأقل.")
        try:
            for path in config.paths:
                ensure_request_in_scope(target, config.method, path)
        except ScopeError as exc:
            raise SafetyViolation(str(exc)) from exc

    def _limit_msg(self, name: str, value: float, limit: float, target: AuthorizedTarget) -> str:
        message = f"{name} ({value:g}) يتجاوز الحد المسموح ({limit:g})."
        settings = self._settings_provider()
        if not target.is_trusted:
            message += " الهدف غير موثَّق الملكية فيبقى على الحدود الافتراضية الآمنة."
        elif not settings.elevated_enabled:
            message += " فعّل «الحدود المرفوعة» من الإعدادات لرفع الحد."
        return message

    # ------------------------------------------------------------------ guard
    def create_guard(self, config: TestConfig, metrics: MetricsCollector) -> "RunGuard":
        return RunGuard(config, metrics)


def peak_users(config: TestConfig) -> int:
    """Highest concurrency a configuration can reach, including engine extras."""
    extra = config.extra
    candidates = [config.users]
    for key in ("max_users", "spike_users", "baseline_users", "start_users"):
        if key in extra:
            try:
                candidates.append(int(extra[key]))
            except (TypeError, ValueError):
                raise SafetyViolation(f"قيمة غير صالحة للحقل {key}.") from None
    return max(candidates)


class RunGuard:
    """Run-time enforcement. Thread-safe: ``request_stop`` may be called from the UI thread."""

    DEADLINE_GRACE_S = 5.0

    def __init__(
        self,
        config: TestConfig,
        metrics: MetricsCollector,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if config.request_budget <= 0:
            raise SafetyViolation("لا يمكن بدء تشغيل بدون ميزانية طلبات محددة.")
        self.config = config
        self._metrics = metrics
        self._clock = clock
        self._limiter = RateLimiter(config.rate_limit_rps, clock)
        self._budget = config.request_budget
        self._issued = 0
        self._exhausted = False
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self.stop_kind = ""
        self.stop_reason = ""
        self._deadline = clock() + config.duration_s + config.timeout_s + self.DEADLINE_GRACE_S
        self._server_errors_only = config.test_type in SERVER_ERROR_GUARD_TYPES

    # ---------------------------------------------------------------- stopping
    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    def request_stop(self, reason: str, kind: str = STOP_USER) -> None:
        with self._lock:
            if self._stop.is_set():
                return
            self.stop_kind, self.stop_reason = kind, reason
            self._stop.set()

    def emergency_stop(self) -> None:
        self.request_stop("إيقاف طارئ بطلب المستخدم", STOP_USER)

    # ---------------------------------------------------------------- limiting
    @property
    def issued(self) -> int:
        with self._lock:
            return self._issued

    @property
    def budget(self) -> int:
        return self._budget

    @property
    def remaining_budget(self) -> int:
        with self._lock:
            return max(0, self._budget - self._issued)

    def reserve(self) -> bool:
        """Reserve one request from the budget (no rate wait). False when not allowed."""
        if self._stop.is_set():
            return False
        with self._lock:
            if self._issued >= self._budget:
                # Requests that were already reserved are allowed to finish; the
                # run is closed by ``budget_stop`` once nothing is in flight.
                self._exhausted = True
                return False
            self._issued += 1
        return True

    @property
    def exhausted(self) -> bool:
        """True once a request was refused because the budget is used up."""
        return self._exhausted

    def budget_stop(self) -> None:
        self.request_stop(f"تم بلوغ ميزانية الطلبات ({self._budget})", STOP_LIMIT)

    async def acquire(self) -> bool:
        """Wait for a rate-limit slot and reserve budget. False means: do not send."""
        if not self.reserve():
            return False
        await self._limiter.acquire()
        return not self._stop.is_set()

    # --------------------------------------------------------------- evaluation
    def evaluate(self) -> None:
        """Apply the automatic stop conditions; called about once per second."""
        if self._stop.is_set():
            return
        if self._clock() > self._deadline:
            self.request_stop("تم بلوغ الحد الأقصى لمدة الاختبار", STOP_LIMIT)
            return
        th = self.config.thresholds
        samples, error_rate, p95, server_rate = self._metrics.window_stats(th.window_s)
        rate = server_rate if self._server_errors_only else error_rate
        if samples >= th.min_samples and rate is not None and rate > th.max_error_rate:
            self.request_stop(
                f"نسبة الأخطاء {rate:.0%} تجاوزت العتبة {th.max_error_rate:.0%} خلال آخر {th.window_s:g} ث",
                STOP_SAFETY,
            )
            return
        if samples >= th.min_samples and p95 is not None and p95 > th.max_p95_ms:
            self.request_stop(
                f"زمن الاستجابة p95 ({p95:.0f} ms) تجاوز العتبة ({th.max_p95_ms:.0f} ms)",
                STOP_SAFETY,
            )
            return
        consecutive = (
            self._metrics.consecutive_server_failures
            if self._server_errors_only
            else self._metrics.consecutive_failures
        )
        if consecutive >= th.max_consecutive_failures:
            self.request_stop(
                f"{consecutive} إخفاقاً متتالياً - الهدف يبدو غير مستقر", STOP_SAFETY
            )
