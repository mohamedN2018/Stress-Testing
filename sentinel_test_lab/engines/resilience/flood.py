"""HTTP flood *resilience assessment*.

A small, bounded, single-source burst used to observe whether the target's
rate limiting reacts (HTTP 429 / Retry-After / RateLimit headers). It is not a
flooding tool: the rate and duration are capped by the safety engine, there is
no proxy rotation or source distribution, and it stops as soon as rate limiting
is clearly active.
"""

from __future__ import annotations

from typing import Any

import httpx

from ...core.models import EngineOutcome, Finding, LoadStage, Severity
from ...core.safety_manager import STOP_LIMIT
from ..base import EngineContext
from ..http_runner import HttpRunner

RATE_LIMIT_HEADERS = (
    "retry-after", "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset", "ratelimit-policy",
    "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset", "x-rate-limit-limit",
)
STOP_AFTER_CONSECUTIVE_429 = 20


class FloodResilienceEngine:
    async def run(self, ctx: EngineContext) -> EngineOutcome:
        config = ctx.config
        state: dict[str, Any] = {
            "first_429_at_request": None, "consecutive_429": 0, "retry_after": None,
            "rate_limit_headers": {}, "first_5xx_at_request": None, "blocked_403": 0,
        }

        def on_response(response: httpx.Response | None, index: int) -> None:
            if response is None:
                return
            for name in RATE_LIMIT_HEADERS:
                if name in response.headers and name not in state["rate_limit_headers"]:
                    state["rate_limit_headers"][name] = response.headers[name]
            if response.status_code == 429:
                state["consecutive_429"] += 1
                if state["first_429_at_request"] is None:
                    state["first_429_at_request"] = index
                    state["retry_after"] = response.headers.get("retry-after")
                    ctx.emit(f"رُصد HTTP 429 عند الطلب رقم {index}")
                if state["consecutive_429"] >= STOP_AFTER_CONSECUTIVE_429:
                    ctx.guard.request_stop("تأكد تفعيل تحديد المعدل (429 متتالية) - إنهاء مبكر", STOP_LIMIT)
            else:
                state["consecutive_429"] = 0
                if response.status_code == 403:
                    state["blocked_403"] += 1
                if response.status_code >= 500 and state["first_5xx_at_request"] is None:
                    state["first_5xx_at_request"] = index

        ctx.emit(
            f"تقييم مقاومة Flood: {config.rate_limit_rps:g} طلب/ث لمدة {config.duration_s:g} ث "
            f"(بحد أقصى {ctx.guard.budget} طلب)"
        )
        async with HttpRunner(ctx, on_response) as runner:
            await runner.run_stages([LoadStage(config.duration_s, config.users, "burst")])

        snap = ctx.metrics.snapshot()
        achieved_rps = round(snap.total / snap.elapsed_s, 2) if snap.elapsed_s > 0 else None
        details = {
            "configured_rps": config.rate_limit_rps,
            "achieved_rps": achieved_rps,
            "requests_sent": snap.total,
            "rate_limited": snap.s429 > 0,
            "count_429": snap.s429,
            "first_429_at_request": state["first_429_at_request"],
            "retry_after": state["retry_after"],
            "rate_limit_headers": state["rate_limit_headers"],
            "count_403": state["blocked_403"],
            "count_5xx": snap.s5xx,
            "first_5xx_at_request": state["first_5xx_at_request"],
        }
        findings: list[Finding] = []
        if snap.total == 0:
            return EngineOutcome(findings, details)
        if snap.s429:
            findings.append(Finding(
                Severity.INFO, "rate-limiting", "تحديد المعدل (Rate limiting) يعمل",
                f"بدأ الرد بـ 429 عند الطلب رقم {state['first_429_at_request']} "
                f"بمعدل {achieved_rps} طلب/ث. Retry-After: {state['retry_after'] or 'غير موجود'}.",
                "" if state["retry_after"] else "أضف ترويسة Retry-After لردود 429 ليتصرف العملاء بشكل صحيح.",
            ))
        elif state["blocked_403"] > snap.total * 0.5:
            findings.append(Finding(
                Severity.INFO, "rate-limiting", "الطلبات حُجبت بـ 403 (WAF/جدار حماية محتمل)",
                f"{state['blocked_403']} من {snap.total} طلب أُجيبت بـ 403.",
            ))
        else:
            findings.append(Finding(
                Severity.MEDIUM, "rate-limiting", "لم يُرصد تحديد للمعدل ضمن حدود الاختبار",
                f"أُرسل {snap.total} طلب بمعدل {achieved_rps} طلب/ث من مصدر واحد دون أي رد 429. "
                "هذا لا يثبت غياب الحماية عند معدلات أعلى، لكنه يعني أن العتبة (إن وُجدت) أعلى من المعدل المختبَر.",
                "فعّل rate limiting على مستوى الـ CDN/WAF أو الخادم (مثل Nginx limit_req أو قواعد Cloudflare).",
            ))
        if snap.s5xx:
            findings.append(Finding(
                Severity.HIGH, "stability", "أخطاء خادم (5xx) تحت معدل منخفض",
                f"{snap.s5xx} رد 5xx، أولها عند الطلب رقم {state['first_5xx_at_request']}.",
                "الخادم يتعثر قبل أن تتدخل الحماية؛ راجع سعة الخادم وضع rate limiting أمامه.",
            ))
        if not state["rate_limit_headers"] and not snap.s429:
            findings.append(Finding(
                Severity.LOW, "rate-limiting", "لا توجد ترويسات RateLimit في الردود",
                "لم تُرصد أي من ترويسات RateLimit-* / X-RateLimit-* / Retry-After.",
            ))
        return EngineOutcome(findings, details)
