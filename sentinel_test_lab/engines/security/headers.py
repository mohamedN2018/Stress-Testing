"""Passive analysis of HTTP response headers."""

from __future__ import annotations

import re

from ...core.models import Finding, Severity

VERSION = re.compile(r"\d+\.\d+")


def analyze_security_headers(headers: dict[str, str], is_https: bool) -> list[Finding]:
    h = {k.lower(): v for k, v in headers.items()}
    findings: list[Finding] = []

    def missing(name: str, severity: Severity, why: str, fix: str) -> None:
        findings.append(Finding(severity, "headers", f"ترويسة {name} غير موجودة", why, fix))

    if is_https:
        hsts = h.get("strict-transport-security")
        if not hsts:
            missing("Strict-Transport-Security", Severity.MEDIUM,
                    "المتصفح قد يتصل عبر HTTP في أول زيارة (هجمات SSL stripping).",
                    "أضف: Strict-Transport-Security: max-age=31536000; includeSubDomains")
        else:
            match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
            if not match or int(match.group(1)) < 15_552_000:
                findings.append(Finding(
                    Severity.LOW, "headers", "قيمة HSTS max-age قصيرة",
                    f"القيمة الحالية: {hsts}", "استخدم max-age لا يقل عن 6 أشهر (15552000).", hsts))
    csp = h.get("content-security-policy")
    if not csp:
        missing("Content-Security-Policy", Severity.MEDIUM,
                "لا توجد سياسة تحد من مصادر السكربتات (تخفيف XSS).",
                "عرّف CSP تبدأ بـ default-src 'self' وشدّدها تدريجياً.")
    elif "'unsafe-inline'" in csp and "script-src" in csp:
        findings.append(Finding(
            Severity.LOW, "headers", "CSP تسمح بـ 'unsafe-inline'",
            "السماح بالسكربتات المضمّنة يُضعف الحماية من XSS.", "استخدم nonces أو hashes بدلاً من unsafe-inline.",
            csp[:200]))
    if "x-frame-options" not in h and "frame-ancestors" not in (csp or ""):
        missing("X-Frame-Options", Severity.MEDIUM, "الصفحة قابلة للتضمين داخل iframe (Clickjacking).",
                "أضف X-Frame-Options: DENY أو CSP frame-ancestors 'none'.")
    if h.get("x-content-type-options", "").lower() != "nosniff":
        missing("X-Content-Type-Options", Severity.LOW, "المتصفح قد يخمّن نوع المحتوى (MIME sniffing).",
                "أضف X-Content-Type-Options: nosniff")
    if "referrer-policy" not in h:
        missing("Referrer-Policy", Severity.LOW, "قد تتسرب عناوين الصفحات إلى مواقع خارجية.",
                "أضف Referrer-Policy: strict-origin-when-cross-origin")
    if "permissions-policy" not in h:
        missing("Permissions-Policy", Severity.INFO, "لا توجد قيود على واجهات المتصفح (كاميرا، موقع...).",
                "أضف Permissions-Policy بما يناسب تطبيقك.")

    for name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        value = h.get(name)
        if not value:
            continue
        if name == "server" and not VERSION.search(value):
            continue  # a bare product name is low-value information
        findings.append(Finding(
            Severity.LOW, "information-disclosure", f"الترويسة {name} تكشف معلومات عن الخادم",
            "معرفة التقنية والإصدار تسهّل استهداف ثغرات معروفة.",
            "أخفِ أو عمّم هذه الترويسة من إعدادات الخادم.", f"{name}: {value}"))
    return findings
