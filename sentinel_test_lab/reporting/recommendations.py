"""Rule-based performance analysis derived strictly from measured data."""

from __future__ import annotations

from typing import Any

from ..core.config import Thresholds
from ..core.models import Finding, Severity, TestType

LOAD_TYPES = {TestType.LOAD, TestType.STRESS, TestType.SPIKE}


def max_sustainable_tested_users(
    test_type: TestType, summary: dict[str, Any], details: dict[str, Any], thresholds: Thresholds
) -> int | None:
    """Highest concurrency that was actually tested and stayed within thresholds.

    Returns None when the run did not establish it. This is never an estimate
    of the server's real maximum capacity.
    """
    if test_type == TestType.STRESS:
        return details.get("max_sustainable_users")
    if test_type not in LOAD_TYPES or not summary.get("total"):
        return None
    if test_type == TestType.SPIKE:
        phases = details.get("phases") or {}
        ok = [
            p.get("users", 0) for p in phases.values()
            if p.get("total") and (p.get("error_rate") or 0) <= thresholds.max_error_rate
            and (p.get("p95_ms") or 0) <= thresholds.max_p95_ms
        ]
        return max(ok) if ok else None
    error_rate = summary.get("error_rate") or 0.0
    p95 = summary.get("p95_ms") or 0.0
    if error_rate <= thresholds.max_error_rate and p95 <= thresholds.max_p95_ms:
        return summary.get("peak_users") or None
    return None


def analyze_performance(
    test_type: TestType, summary: dict[str, Any], series: list[dict[str, Any]]
) -> list[Finding]:
    """Bottleneck indicators and recommendations for load-type runs."""
    findings: list[Finding] = []
    total = summary.get("total") or 0
    if test_type not in LOAD_TYPES or total == 0:
        return findings
    error_rate = summary.get("error_rate") or 0.0
    p50, p95, p99 = summary.get("p50_ms"), summary.get("p95_ms"), summary.get("p99_ms")

    if summary.get("transport_errors"):
        kinds = ", ".join(f"{k}×{v}" for k, v in (summary.get("error_kinds") or {}).items())
        findings.append(Finding(
            Severity.HIGH if summary["transport_errors"] / total > 0.05 else Severity.MEDIUM,
            "bottleneck", "أخطاء اتصال/مهلات أثناء الاختبار",
            f"{summary['transport_errors']} طلب فشل على مستوى الاتصال ({kinds}).",
            "راجع حدود الاتصالات المتزامنة (workers / backlog / keep-alive) ومهلات الخادم والـ proxy."))
    if summary.get("s5xx"):
        findings.append(Finding(
            Severity.HIGH, "bottleneck", "أخطاء خادم (5xx) تحت الحمل",
            f"{summary['s5xx']} رد 5xx من {total} طلب.",
            "افحص سجلات التطبيق وقت الاختبار: استنزاف اتصالات قاعدة البيانات، الذاكرة، أو مهلات الـ upstream."))
    if summary.get("s429"):
        findings.append(Finding(
            Severity.INFO, "rate-limiting", "الخادم قيّد المعدل (HTTP 429) أثناء الاختبار",
            f"{summary['s429']} رد 429. نتائج الأداء تعكس سلوك الحماية وليس السعة فقط.",
            "اختبر من عنوان مستثنى من التقييد إن أردت قياس السعة الصافية."))
    if error_rate > 0.01 and not findings:
        findings.append(Finding(
            Severity.MEDIUM, "bottleneck", f"نسبة أخطاء {error_rate:.1%}",
            f"{summary.get('failed')} طلب فاشل من {total} (أغلبها 4xx).",
            "تحقق من صحة المسارات المختبَرة ومن أن الأخطاء ليست ناتجة عن الاختبار نفسه."))
    if p50 and p99 and p99 > max(5 * p50, p50 + 500):
        findings.append(Finding(
            Severity.MEDIUM, "bottleneck", "ذيل زمن استجابة طويل (tail latency)",
            f"p50 = {p50} ms بينما p99 = {p99} ms.",
            "ذيل طويل يشير غالباً إلى تزاحم على مورد (أقفال قاعدة البيانات، GC، طوابير workers)."))
    if p95 and p95 > 2000:
        findings.append(Finding(
            Severity.MEDIUM, "bottleneck", "زمن استجابة مرتفع",
            f"p95 = {p95} ms.", "حلّل الاستعلامات البطيئة وأضف كاشاً للصفحات والاستعلامات المتكررة."))

    # Latency growth as concurrency increases
    points = [s for s in series if s.get("requests") and s.get("avg_ms") is not None]
    if len(points) >= 6:
        low_users = min(s["users"] for s in points)
        high_users = max(s["users"] for s in points)
        if high_users >= 2 * max(low_users, 1):
            low = [s["avg_ms"] for s in points if s["users"] <= low_users + (high_users - low_users) * 0.25]
            high = [s["avg_ms"] for s in points if s["users"] >= high_users - (high_users - low_users) * 0.25]
            if low and high:
                low_avg, high_avg = sum(low) / len(low), sum(high) / len(high)
                if low_avg > 0 and high_avg > 2 * low_avg and high_avg - low_avg > 50:
                    findings.append(Finding(
                        Severity.MEDIUM, "bottleneck", "زمن الاستجابة يتضاعف مع زيادة التزامن",
                        f"المتوسط ارتفع من {low_avg:.0f} ms عند ~{low_users} مستخدم إلى "
                        f"{high_avg:.0f} ms عند ~{high_users} مستخدم.",
                        "الخادم يقترب من حد المعالجة المتزامنة؛ زد عدد الـ workers أو حسّن الاستعلامات."))
    if not findings:
        findings.append(Finding(
            Severity.INFO, "performance", "لم تُرصد اختناقات ضمن الحمل المختبَر",
            f"{total} طلب بنسبة أخطاء {error_rate:.1%} و p95 = {p95} ms."))
    return findings


def executive_summary(record_dict: dict[str, Any]) -> list[str]:
    """Plain-language summary sentences built only from recorded values."""
    summary = record_dict.get("summary") or {}
    findings = record_dict.get("findings") or []
    lines: list[str] = []
    total = summary.get("total") or 0
    if total and record_dict.get("test_type") in ("security", "ddos_posture", "brute_force"):
        lines.append(
            f"أُرسل {total} طلب فحص خلال {summary.get('elapsed_s', 0):g} ثانية. ردود 4xx ضمنها متوقعة "
            "(فحص ملفات يجب ألا تكون موجودة أو محاولات دخول خاطئة متعمدة) وليست أخطاء أداء."
        )
    elif total:
        rate = summary.get("error_rate") or 0.0
        lines.append(
            f"أُرسل {total} طلب خلال {summary.get('elapsed_s', 0):g} ثانية بمتوسط "
            f"{summary.get('rps') or 0:g} طلب/ث؛ نجح {summary.get('success', 0)} وفشل "
            f"{summary.get('failed', 0)} (نسبة الأخطاء {rate:.1%})."
        )
        if summary.get("p95_ms") is not None:
            lines.append(
                f"زمن الاستجابة: المتوسط {summary.get('avg_ms')} ms، p50 = {summary.get('p50_ms')} ms، "
                f"p95 = {summary.get('p95_ms')} ms، p99 = {summary.get('p99_ms')} ms."
            )
    else:
        lines.append("لم تُسجَّل أي طلبات في هذا التشغيل.")
    sustainable = summary.get("max_sustainable_tested_users")
    if sustainable:
        lines.append(
            f"أعلى تزامن تم اختباره وبقي ضمن العتبات: {sustainable} مستخدم. "
            "هذه ليست السعة القصوى للخادم، بل أعلى مستوى أثبته هذا الاختبار."
        )
    elif record_dict.get("test_type") in ("load", "stress", "spike"):
        lines.append("لم يثبت هذا الاختبار مستوى تزامن مستداماً ضمن العتبات المحددة.")
    counts = {sev: sum(1 for f in findings if f.get("severity") == sev) for sev in ("high", "medium", "low")}
    if any(counts.values()):
        lines.append(
            f"الملاحظات: {counts['high']} عالية، {counts['medium']} متوسطة، {counts['low']} منخفضة الخطورة."
        )
    posture = (record_dict.get("details") or {}).get("posture")
    if posture:
        lines.append(
            f"مؤشر الوضع الأمني: {posture['grade']} ({posture['score']} من 100) — مؤشر تقريبي لما فُحص في هذا التشغيل فقط.")
    if record_dict.get("stop_reason"):
        lines.append(f"سبب التوقف: {record_dict['stop_reason']}.")
    return lines
