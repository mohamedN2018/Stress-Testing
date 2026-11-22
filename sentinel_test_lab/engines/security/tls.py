"""TLS configuration assessment (handshake-only, no payloads)."""

from __future__ import annotations

import ssl
from typing import Any

from ...core.models import AuthorizedTarget, Finding, Severity
from ...core.tls_info import fetch_tls_info, probe_protocol

LEGACY = (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1))


async def assess_tls(target: AuthorizedTarget) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    if target.scheme != "https":
        severity = Severity.LOW if target.is_local else Severity.HIGH
        findings.append(Finding(
            severity, "tls", "الهدف يعمل عبر HTTP بدون تشفير",
            "كل البيانات تنتقل كنص صريح.", "فعّل HTTPS بشهادة صالحة وحوّل HTTP إليه."))
        return findings, {"available": False, "note": "الهدف ليس HTTPS"}

    info = await fetch_tls_info(target.host, target.port)
    details: dict[str, Any] = info.to_dict()
    if not info.available:
        findings.append(Finding(Severity.HIGH, "tls", "فشل مصافحة TLS", info.error))
        return findings, details
    if info.trusted is False:
        findings.append(Finding(
            Severity.HIGH, "tls", "شهادة TLS غير موثوقة", info.trust_error,
            "استخدم شهادة صادرة من جهة موثوقة ومطابقة لاسم النطاق (مثل Let's Encrypt)."))
    if info.days_remaining is not None:
        if info.days_remaining < 0:
            findings.append(Finding(Severity.HIGH, "tls", "شهادة TLS منتهية الصلاحية",
                                    f"انتهت في {info.not_after}.", "جدّد الشهادة فوراً."))
        elif info.days_remaining < 21:
            findings.append(Finding(Severity.MEDIUM, "tls", "شهادة TLS تنتهي قريباً",
                                    f"متبقٍ {info.days_remaining} يوماً.", "فعّل التجديد التلقائي."))
    if info.protocol in ("TLSv1", "TLSv1.1"):
        findings.append(Finding(Severity.HIGH, "tls", f"المصافحة تمت ببروتوكول قديم ({info.protocol})",
                                "", "عطّل TLS 1.0/1.1 وفعّل TLS 1.2 و 1.3."))

    legacy: dict[str, bool | None] = {}
    for label, version in LEGACY:
        accepted = await probe_protocol(target.host, target.port, version)
        legacy[label] = accepted
        if accepted:
            findings.append(Finding(
                Severity.MEDIUM, "tls", f"الخادم يقبل {label}",
                "بروتوكول قديم به نقاط ضعف معروفة.", "اجعل الحد الأدنى TLS 1.2."))
    details["legacy_protocols"] = legacy  # None = could not be probed from this machine
    return findings, details
