"""Basic misconfiguration indicators using a few read-only GET requests.

Nothing is exploited and no content is stored: each check only records whether
a tell-tale signature is present.
"""

from __future__ import annotations

import secrets
from typing import Any

from ...core.authorization import ScopeError
from ...core.models import Finding, Severity
from ..http_runner import ScopedHttp

DJANGO_DEBUG_MARKERS = ("You're seeing this error because you have <code>DEBUG = True</code>",
                        "Django tried these URL patterns")
STACK_TRACE_MARKERS = ("Traceback (most recent call last)", "Whoops, looks like something went wrong",
                       "Fatal error:", "at System.Web.", "Stack trace:")


async def _get(http: ScopedHttp, path: str, **kwargs: Any):  # type: ignore[no-untyped-def]
    try:
        return await http.request("GET", path, **kwargs)
    except ScopeError:
        return None  # outside the authorized paths: skip silently


async def assess_misconfiguration(http: ScopedHttp) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    checks: dict[str, Any] = {}

    # 1) Verbose error pages on a random non-existent path
    response = await _get(http, f"/sentinel-probe-{secrets.token_hex(6)}")
    if response is not None:
        body = response.text[:60000]
        checks["not_found_status"] = response.status_code
        if any(m in body for m in DJANGO_DEBUG_MARKERS):
            findings.append(Finding(
                Severity.HIGH, "misconfiguration", "Django يعمل بوضع DEBUG = True",
                "صفحة 404 تكشف مسارات الـ URL وإعدادات داخلية.",
                "اجعل DEBUG = False في الإنتاج واضبط ALLOWED_HOSTS."))
        elif any(m in body for m in STACK_TRACE_MARKERS):
            findings.append(Finding(
                Severity.MEDIUM, "misconfiguration", "صفحات الأخطاء تكشف تفاصيل داخلية (stack trace)",
                "", "اعرض صفحات خطأ عامة وسجّل التفاصيل في الخادم فقط."))
        if response.status_code == 200:
            checks["soft_404"] = True

    # 2) Sensitive files that must never be public (signature check only)
    soft_404 = checks.get("soft_404", False)
    for path, marker, title in (
        ("/.git/HEAD", "ref:", "مجلد ‎.git مكشوف للعموم"),
        ("/.env", "=", "ملف ‎.env مكشوف للعموم"),
    ):
        response = await _get(http, path)
        exposed = False
        if response is not None and response.status_code == 200 and not soft_404:
            head = response.text[:300]
            content_type = response.headers.get("content-type", "")
            exposed = marker in head and "html" not in content_type.lower() and "<html" not in head.lower()
        checks[path] = exposed if response is not None else None
        if exposed:
            findings.append(Finding(
                Severity.HIGH, "misconfiguration", title,
                "ملف حساس متاح للتنزيل (قد يحوي أسراراً أو الشيفرة المصدرية).",
                "امنع الوصول للملفات المخفية من إعدادات الخادم وغيّر أي أسرار مكشوفة.", path))

    # 3) Directory listing on the root
    response = await _get(http, "/")
    if response is not None:
        body = response.text[:5000]
        if "<title>Index of /" in body or "Directory listing for /" in body:
            findings.append(Finding(
                Severity.MEDIUM, "misconfiguration", "استعراض المجلدات (Directory listing) مفعّل",
                "", "عطّل autoindex في إعدادات الخادم."))

    # 4) Permissive CORS
    evil = "https://sentinel-cors-probe.example"
    response = await _get(http, "/", headers={"Origin": evil})
    if response is not None:
        acao = response.headers.get("access-control-allow-origin", "")
        creds = response.headers.get("access-control-allow-credentials", "").lower() == "true"
        checks["cors_allow_origin"] = acao
        if acao == evil and creds:
            findings.append(Finding(
                Severity.HIGH, "misconfiguration", "CORS يعكس أي Origin مع السماح بالـ credentials",
                "أي موقع خارجي يستطيع قراءة ردود المستخدم المسجَّل.",
                "قيّد Access-Control-Allow-Origin بقائمة نطاقات محددة.", f"ACAO: {acao}"))
        elif acao == evil or (acao == "*" and creds):
            findings.append(Finding(
                Severity.MEDIUM, "misconfiguration", "إعداد CORS متساهل",
                f"Access-Control-Allow-Origin: {acao}", "قيّد النطاقات المسموحة."))

    # 5) security.txt (informational)
    response = await _get(http, "/.well-known/security.txt")
    if response is not None:
        present = response.status_code == 200 and "contact:" in response.text[:2000].lower()
        checks["security_txt"] = present
        if not present:
            findings.append(Finding(
                Severity.INFO, "misconfiguration", "لا يوجد ملف security.txt",
                "", "أضف ‎/.well-known/security.txt لتسهيل الإبلاغ عن الثغرات."))
    return findings, checks
