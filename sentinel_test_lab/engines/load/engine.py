"""Load testing: ramp up to a fixed number of virtual users and hold."""

from __future__ import annotations

from ...core.models import EngineOutcome, LoadStage, TestConfig
from ..base import EngineContext
from ..http_runner import HttpRunner

# Safe presets (virtual users). "Custom" is whatever the safety limits allow.
PRESETS: dict[str, int] = {"Baseline": 5, "Light": 10, "Moderate": 25, "Elevated": 50}


def build_stages(config: TestConfig) -> list[LoadStage]:
    ramp = max(0.0, min(config.ramp_up_s, config.duration_s))
    stages: list[LoadStage] = []
    if ramp > 0:
        stages.append(LoadStage(ramp, config.users, "ramp-up", ramp=True))
    hold = config.duration_s - ramp
    if hold > 0:
        stages.append(LoadStage(hold, config.users, "steady"))
    return stages


class LoadEngine:
    async def run(self, ctx: EngineContext) -> EngineOutcome:
        stages = build_stages(ctx.config)
        ctx.emit(f"بدء اختبار الحمل: {ctx.config.users} مستخدم لمدة {ctx.config.duration_s:g} ث")
        async with HttpRunner(ctx) as runner:
            await runner.run_stages(stages)
        return EngineOutcome(details={"phases": ctx.metrics.all_phases()})
