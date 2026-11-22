"""Brute-force *protection* assessment (defensive).

Sends a small, capped number of failed logins for one dedicated test account
using randomly generated (deliberately wrong) passwords, and observes how the
login endpoint reacts: HTTP 429, lockout, CAPTCHA, growing delays. It never
uses password lists, never targets real users and never tries to log in.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import secrets
from typing import Any

from ...core.authorization import ScopeError
from ...core.models import EngineOutcome, Finding, Severity
from ..base import EngineContext
from ..http_runner import ScopedHttp
from ..security.headers import analyze_security_headers

LOCKOUT_PATTERNS = re.compile(
    r"too many|locked|lockout|temporarily blocked|try again later|rate limit|"
    r"محظور|مقفل|محاولات كثيرة|حاول لاحق",
    re.IGNORECASE,
)
CAPTCHA_PATTERNS = re.compile(r"captcha|recaptcha|hcaptcha|turnstile|cf-challenge", re.IGNORECASE)
HIDDEN_INPUT = re.compile(
    r"<input[^>]*type=[\"']hidden[\"'][^>]*>", re.IGNORECASE
)
ATTR = re.compile(r"(name|value)=[\"']([^\"']*)[\"']", re.IGNORECASE)


def extract_hidden_field(html: str, field_name: str) -> str | None:
    """Value of a hidden form input (e.g. Django's ``csrfmiddlewaretoken``)."""
    for tag in HIDDEN_INPUT.findall(html):
        attrs = {k.lower(): v for k, v in ATTR.findall(tag)}
        if attrs.get("name") == field_name:
            return attrs.get("value", "")
    return None


class BruteForceProtectionEngine:
    async def run(self, ctx: EngineContext) -> EngineOutcome:
        config, extra = ctx.config, ctx.config.extra
        login_path = str(extra.get("login_path", "/login"))
        username_field = str(extra.get("username_field", "username"))
        password_field = str(extra.get("password_field", "password"))
        username = str(extra.get("test_username", ""))
        attempts = int(extra.get("attempts", 5))
        as_json = extra.get("content_type") == "json"
        csrf_field = str(extra.get("csrf_field", "csrfmiddlewaretoken"))
        mfa = str(extra.get("mfa", "unknown"))  # manual input: yes / no / unknown

        findings: list[Finding] = []
        observations: list[dict[str, Any]] = []
        details: dict[str, Any] = {
            "login_path": login_path, "attempts_planned": attempts, "attempts": observations,
            "mfa_declared": mfa, "protection_detected": None, "trigger_attempt": None,
        }

        async with ctx.new_client(max_connections=2) as client:
            http = ScopedHttp(ctx, client)
            try:
                page = await http.request("GET", login_path)
            except ScopeError as exc:
                findings.append(Finding(Severity.INFO, "scope", "مسار الدخول خارج النطاق المصرّح", str(exc)))
                return EngineOutcome(findings, details)

            csrf_value = None
            if page is not None:
                details["login_page_status"] = page.status_code
                findings.extend(analyze_security_headers(dict(page.headers), ctx.target.scheme == "https"))
                csrf_value = extract_hidden_field(page.text, csrf_field)
                if CAPTCHA_PATTERNS.search(page.text):
                    details["captcha_on_page"] = True
            if ctx.target.scheme != "https" and not ctx.target.is_local:
                findings.append(Finding(
                    Severity.HIGH, "transport", "صفحة الدخول تعمل عبر HTTP غير مشفَّر",
                    "بيانات الدخول تُرسل بدون تشفير.", "افرض HTTPS على كل مسارات المصادقة.",
                ))

            trigger: str | None = None
            baseline_sig: tuple[int, str] | None = None
            for number in range(1, attempts + 1):
                if ctx.guard.stopped:
                    break
                payload = {username_field: username, password_field: secrets.token_urlsafe(12)}
                if csrf_value is not None:
                    payload[csrf_field] = csrf_value
                headers = {"Referer": ctx.target.base_url + login_path}
                kwargs: dict[str, Any] = {"json": payload} if as_json else {"data": payload}
                try:
                    response = await http.request("POST", login_path, headers=headers, **kwargs)
                except ScopeError as exc:
                    findings.append(Finding(
                        Severity.INFO, "scope", "طريقة POST غير مصرّح بها لهذا الهدف", str(exc),
                        "أضف POST إلى الطرق المسموحة للهدف من صفحة «اختبار جديد» ثم أعد التقييم.",
                    ))
                    return EngineOutcome(findings, details)
                if response is None:
                    observations.append({"attempt": number, "status": None})
                    continue
                body = response.text[:20000]
                signature = (response.status_code, hashlib.sha256(body.encode()).hexdigest()[:12])
                observation = {
                    "attempt": number,
                    "status": response.status_code,
                    "latency_ms": round(response.elapsed.total_seconds() * 1000, 1),
                    "retry_after": response.headers.get("retry-after"),
                    "body_length": len(body),
                }
                observations.append(observation)
                if baseline_sig is None:
                    baseline_sig = signature
                if response.status_code == 429:
                    trigger = "HTTP 429"
                elif response.status_code in (423, 403) and baseline_sig[0] != response.status_code:
                    trigger = f"تغيّر الرد إلى HTTP {response.status_code} (قفل/حجب)"
                elif CAPTCHA_PATTERNS.search(body) and not details.get("captcha_on_page"):
                    trigger = "ظهور CAPTCHA"
                elif number > 1 and LOCKOUT_PATTERNS.search(body) and signature != baseline_sig:
                    trigger = "رسالة قفل/تقييد في الرد"
                if trigger:
                    details["trigger_attempt"] = number
                    ctx.emit(f"رُصدت حماية عند المحاولة {number}: {trigger}")
                    break  # protection confirmed: no reason to send more attempts
                # refresh CSRF token if the page rotates it
                refreshed = extract_hidden_field(body, csrf_field)
                if refreshed:
                    csrf_value = refreshed
                await asyncio.sleep(config.interval_s)

        sent = [o for o in observations if o.get("status") is not None]
        latencies = [o["latency_ms"] for o in sent]
        progressive_delay = (
            len(latencies) >= 4 and latencies[-1] > max(500.0, latencies[0] * 3)
        )
        details["progressive_delay"] = progressive_delay
        details["protection_detected"] = bool(trigger or progressive_delay) if sent else None
        details["trigger"] = trigger or ("تأخير متزايد" if progressive_delay else None)

        if not sent:
            findings.append(Finding(
                Severity.INFO, "auth", "تعذّر إجراء التقييم", "لم تصل أي محاولة إلى نقطة الدخول."
            ))
        elif trigger:
            findings.append(Finding(
                Severity.INFO, "auth", "حماية من التخمين مفعّلة",
                f"رُصد «{trigger}» بعد {details['trigger_attempt']} محاولة فاشلة.",
            ))
        elif progressive_delay:
            findings.append(Finding(
                Severity.INFO, "auth", "تأخير متزايد بين المحاولات الفاشلة",
                f"زمن الرد ارتفع من {latencies[0]} ms إلى {latencies[-1]} ms.",
            ))
        else:
            findings.append(Finding(
                Severity.HIGH, "auth", "لم تُرصد حماية من التخمين ضمن حدود الاختبار",
                f"{len(sent)} محاولة دخول فاشلة متتالية لحساب الاختبار دون 429 أو قفل أو CAPTCHA أو تأخير.",
                "فعّل rate limiting وقفل الحساب المؤقت بعد عدد محدود من المحاولات "
                "(مثل django-axes أو django-ratelimit) وأضف CAPTCHA بعد الإخفاقات المتكررة.",
            ))
        if mfa == "no":
            findings.append(Finding(
                Severity.MEDIUM, "auth", "المصادقة متعددة العوامل (MFA) غير مفعّلة",
                "حسب ما أدخلته يدوياً.", "فعّل MFA على الأقل لحسابات الإدارة.",
            ))
        elif mfa == "unknown":
            findings.append(Finding(
                Severity.INFO, "auth", "حالة MFA غير محددة",
                "لا يمكن اكتشاف MFA آلياً؛ حدّدها يدوياً في نموذج التقييم.",
            ))
        return EngineOutcome(findings, details)


__all__ = ["BruteForceProtectionEngine", "extract_hidden_field"]
