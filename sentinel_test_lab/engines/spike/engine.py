"""Spike testing: baseline -> sudden controlled increase -> recovery."""

from __future__ import annotations

from typing import Any

from ...core.models import EngineOutcome, Finding, LoadStage, Severity, TestConfig
from ..base import EngineContext
from ..http_runner import HttpRunner

BASELINE, SPIKE, RECOVERY = "baseline", "spike", "recovery"


def build_stages(config: TestConfig) -> list[LoadStage]:
    extra = config.extra
    baseline_users = max(1, int(extra.get("baseline_users", 1)))
    spike_users = max(baseline_users, int(extra.get("spike_users", config.users)))
    return [
        LoadStage(float(extra.get("baseline_s", 10)), baseline_users, BASELINE),
        LoadStage(float(extra.get("spike_s", 10)), spike_users, SPIKE),
        LoadStage(float(extra.get("recovery_s", 10)), baseline_users, RECOVERY),
    ]


def _ratio(after: float | None, before: float | None) -> float | None:
    if after is None or not before:
        return None
    return round(after / before, 2)


class SpikeEngine:
    RECOVERY_TOLERANCE = 1.5  # recovery p95 may be up to 1.5x the baseline p95

    async def run(self, ctx: EngineContext) -> EngineOutcome:
        stages = build_stages(ctx.config)
        ctx.emit(
            f"بدء اختبار القفزة: {stages[0].users} ← {stages[1].users} ← {stages[2].users} مستخدم"
        )
        async with HttpRunner(ctx) as runner:
            await runner.run_stages(stages)

        phases = ctx.metrics.all_phases()
        base, spike, rec = (phases.get(k) for k in (BASELINE, SPIKE, RECOVERY))
        details: dict[str, Any] = {"phases": phases, "completed": rec is not None and not ctx.guard.stopped}
        findings: list[Finding] = []
        if base and spike:
            details["spike_vs_baseline_p95"] = _ratio(spike.get("p95_ms"), base.get("p95_ms"))
            details["spike_error_rate"] = spike.get("error_rate")
        if base and rec and rec.get("total"):
            ratio = _ratio(rec.get("p95_ms"), base.get("p95_ms"))
            details["recovery_vs_baseline_p95"] = ratio
            base_err = base.get("error_rate") or 0.0
            rec_err = rec.get("error_rate") or 0.0
            recovered = (ratio is None or ratio <= self.RECOVERY_TOLERANCE) and rec_err <= base_err + 0.02
            details["recovered"] = recovered
            if recovered:
                findings.append(Finding(
                    Severity.INFO, "performance", "النظام تعافى بعد القفزة",
                    f"p95 بعد القفزة يساوي {ratio if ratio is not None else '—'}× قيمته قبلها.",
                ))
            else:
                findings.append(Finding(
                    Severity.MEDIUM, "performance", "النظام لم يتعافَ كاملاً بعد القفزة",
                    f"p95 بعد القفزة = {rec.get('p95_ms')} ms مقابل {base.get('p95_ms')} ms قبلها، "
                    f"ونسبة الأخطاء بعدها {rec_err:.1%}.",
                    "راجع إعدادات الـ connection pool و autoscaling وطوابير المهام.",
                ))
        else:
            details["recovered"] = None  # not measured: the run ended before recovery
        if spike and (spike.get("error_rate") or 0) > 0.05:
            findings.append(Finding(
                Severity.MEDIUM, "performance", "أخطاء أثناء القفزة",
                f"نسبة الأخطاء أثناء القفزة {spike['error_rate']:.1%}.",
                "أضف rate limiting أو طابور انتظار أو كاش للصفحات الأكثر طلباً.",
            ))
        return EngineOutcome(findings=findings, details=details)
