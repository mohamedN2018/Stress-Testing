"""Shared Arabic labels for enums (UI and reports). Technical terms stay in English."""

from __future__ import annotations

from .models import Backend, Environment, RunStatus, Severity, TestType

NOT_AVAILABLE = "غير متاح"

TEST_TYPE_LABELS: dict[str, str] = {
    TestType.LOAD.value: "اختبار الحمل (Load)",
    TestType.STRESS.value: "اختبار الإجهاد (Stress)",
    TestType.SPIKE.value: "اختبار القفزة (Spike)",
    TestType.FLOOD.value: "تقييم مقاومة HTTP Flood",
    TestType.DDOS_POSTURE.value: "تقييم الجاهزية ضد DDoS",
    TestType.BRUTE_FORCE.value: "تقييم الحماية من Brute Force",
    TestType.SECURITY.value: "تقييم الثغرات والإعدادات الأمنية",
}

TEST_TYPE_SHORT: dict[str, str] = {
    TestType.LOAD.value: "حمل", TestType.STRESS.value: "إجهاد", TestType.SPIKE.value: "قفزة",
    TestType.FLOOD.value: "Flood", TestType.DDOS_POSTURE.value: "DDoS",
    TestType.BRUTE_FORCE.value: "Brute Force", TestType.SECURITY.value: "أمني",
}
# Only these types measure performance; for the assessments, 4xx answers are expected probe results.
PERFORMANCE_TYPES = {TestType.LOAD.value, TestType.STRESS.value, TestType.SPIKE.value, TestType.FLOOD.value}

STATUS_LABELS: dict[str, str] = {
    RunStatus.RUNNING.value: "قيد التشغيل",
    RunStatus.COMPLETED.value: "مكتمل",
    RunStatus.STOPPED.value: "أوقفه المستخدم",
    RunStatus.AUTO_STOPPED.value: "إيقاف تلقائي (محرك الأمان)",
    RunStatus.FAILED.value: "فشل",
}

SEVERITY_LABELS: dict[str, str] = {
    Severity.INFO.value: "معلومة",
    Severity.LOW.value: "منخفضة",
    Severity.MEDIUM.value: "متوسطة",
    Severity.HIGH.value: "عالية",
}

ENVIRONMENT_LABELS: dict[str, str] = {
    Environment.PRODUCTION.value: "إنتاج (Production)",
    Environment.STAGING.value: "تجريبي (Staging)",
    Environment.LOCALHOST.value: "محلي (Localhost)",
}

BACKEND_LABELS: dict[str, str] = {
    Backend.INTERNAL.value: "المحرك الداخلي (httpx)",
    Backend.LOCUST.value: "Locust",
    Backend.K6.value: "k6",
}


def label(mapping: dict[str, str], key: object) -> str:
    return mapping.get(str(getattr(key, "value", key)), str(key))
