"""Stress testing: step the load up gradually and stop at the first failing step.

The result is the *highest load level that was tested and stayed within the
configured thresholds*. It is not a claim about the server's true maximum.
"""

from __future__ import annotations

from typing import Any

from ...core.models import EngineOutcome, Finding, LoadStage, Severity, TestConfig
from ...core.safety_manager import STOP_LIMIT, STOP_SAFETY
from ..base import EngineContext
from ..http_runner import HttpRunner


def build_steps(config: TestConfig) -> list[LoadStage]:
    extra = config.extra
    start = max(1, int(extra.get("start_users", 1)))
    step = max(1, int(extra.get("step_users", 1)))
    maximum = max(start, int(extra.get("max_users", config.users)))
    step_duration = max(1.0, float(extra.get("step_duration_s", 10)))
    stages: list[LoadStage] = []
    users, total = start, 0.0
    while users <= maximum and total + step_duration <= config.duration_s + 1e-9:
        stages.append(LoadStage(step_duration, users, f"step-{users}"))
        total += step_duration
        if users == maximum:
            break
        users = min(maximum, users + step)
    return stages


class StressEngine:
    MIN_STEP_SAMPLES = 5

    async def run(self, ctx: EngineContext) -> EngineOutcome:
        config, thresholds = ctx.config, ctx.config.thresholds
        stages = build_steps(config)
        steps: list[dict[str, Any]] = []
        sustainable: int | None = None
        breaking: int | None = None

        def evaluate(stage: LoadStage) -> bool:
            """Judge one finished step against the thresholds; True when it passed."""
            nonlocal sustainable, breaking
            stats = ctx.metrics.phase_stats(stage.label) or {}
            error_rate = stats.get("error_rate")
            p95 = stats.get("p95_ms")
            enough = stats.get("total", 0) >= self.MIN_STEP_SAMPLES
            reasons = []
            if not enough:
                reasons.append("عينات غير كافية للحكم")
            if error_rate is not None and error_rate > thresholds.max_error_rate:
                reasons.append(f"نسبة الأخطاء {error_rate:.1%}")
            if p95 is not None and p95 > thresholds.max_p95_ms:
                reasons.append(f"p95 = {p95:.0f} ms")
            passed = not reasons
            steps.append({"users": stage.users, "passed": passed, "reasons": reasons, **stats})
            if passed:
                sustainable = stage.users
                ctx.emit(f"المرحلة {stage.users} مستخدم: ضمن العتبات")
                return True
            if enough:
                breaking = stage.users
                ctx.guard.request_stop(
                    f"تجاوز العتبات عند {stage.users} مستخدم ({'، '.join(reasons)})", STOP_SAFETY
                )
            return False

        async def after_stage(stage: LoadStage) -> bool:
            return evaluate(stage)

        ctx.emit(f"بدء اختبار الإجهاد: {len(stages)} مراحل حتى {stages[-1].users if stages else 0} مستخدم")
        async with HttpRunner(ctx) as runner:
            await runner.run_stages(stages, after_stage)

        # A step interrupted by the safety guard is recorded as failed.
        evaluated = {s["users"] for s in steps}
        for stage in stages:
            stats = ctx.metrics.phase_stats(stage.label)
            if stats and stage.users not in evaluated:
                nearly_complete = stats.get("duration_s", 0) >= 0.8 * stage.duration_s
                if ctx.guard.stop_kind == STOP_LIMIT and nearly_complete:
                    evaluate(stage)  # ended by the request budget right at the end of the step
                    continue
                failed_by_guard = ctx.guard.stop_kind == STOP_SAFETY
                steps.append({
                    "users": stage.users, "passed": False,
                    "reasons": [ctx.guard.stop_reason or "لم تكتمل المرحلة"], **stats,
                })
                if failed_by_guard and breaking is None:
                    breaking = stage.users

        planned_max = stages[-1].users if stages else 0
        details = {
            "steps": steps,
            "max_sustainable_users": sustainable,
            "first_failing_users": breaking,
            "planned_max_users": planned_max,
            "limit_reached": breaking is not None,
        }
        findings: list[Finding] = []
        if breaking is not None:
            findings.append(Finding(
                Severity.MEDIUM, "performance",
                f"تدهور الأداء عند {breaking} مستخدماً متزامناً",
                f"أعلى حمل تم اختباره وبقي ضمن العتبات: {sustainable if sustainable is not None else 'لا يوجد'} مستخدم.",
                "راجع اختناقات الخادم (قاعدة البيانات، عدد الـ workers، الكاش) ثم أعد الاختبار.",
            ))
        elif sustainable is not None:
            findings.append(Finding(
                Severity.INFO, "performance",
                f"لم يُبلَغ حد الأداء حتى {sustainable} مستخدماً",
                "الاختبار لم يصل إلى نقطة تدهور ضمن الحمل المصرّح به؛ السعة القصوى الفعلية غير محددة.",
                "لتحديد الحد الفعلي أعد الاختبار بحمل أعلى ضمن حدود التصريح.",
            ))
        return EngineOutcome(findings=findings, details=details)
