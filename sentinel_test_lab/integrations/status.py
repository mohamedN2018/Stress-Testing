"""Availability of the optional integrations, as shown in the UI."""

from __future__ import annotations

from dataclasses import dataclass

from ..core.config import Settings
from ..core.secrets_store import CLOUDFLARE_TOKEN, ZAP_API_KEY, SecretStore
from .k6.adapter import find_k6
from .locust.adapter import find_locust
from .zap.client import ZapClient
from .zap.daemon import ZapDaemon, local_daemon


@dataclass(frozen=True)
class IntegrationStatus:
    name: str
    available: bool | None  # None = configured but not checked yet
    detail: str


def local_status(settings: Settings, secrets: SecretStore) -> list[IntegrationStatus]:
    """Checks that need no network access (safe to call on the UI thread)."""
    locust = find_locust(settings)
    k6 = find_k6(settings)
    has_cf = bool(secrets.get(CLOUDFLARE_TOKEN))
    return [
        IntegrationStatus("المحرك الداخلي (httpx)", True, "مدمج — يعمل دائماً"),
        IntegrationStatus("Locust", locust is not None,
                          " ".join(locust) if locust else "غير مثبت (pip install locust)"),
        IntegrationStatus("k6", k6 is not None, k6[0] if k6 else "غير مثبت أو غير موجود في PATH"),
        _zap_local_status(settings),
        IntegrationStatus("Cloudflare API", has_cf,
                          "token محفوظ في مخزن بيانات الاعتماد" if has_cf else "لا يوجد token (اختياري)"),
    ]


def _zap_local_status(settings: Settings) -> IntegrationStatus:
    daemon = local_daemon()
    if daemon.running:
        return IntegrationStatus("OWASP ZAP", True, f"يعمل محلياً — الإصدار {daemon.version}")
    if settings.zap_url:
        return IntegrationStatus("OWASP ZAP", None, f"{settings.zap_url} — اضغط «فحص الاتصال»")
    reason = ZapDaemon.unavailable_reason(settings)
    if not reason:
        return IntegrationStatus("OWASP ZAP", True, "مثبت — يُشغَّل تلقائياً عند اختيار فحص ZAP")
    return IntegrationStatus("OWASP ZAP", False, reason)


async def zap_status(settings: Settings, secrets: SecretStore) -> IntegrationStatus:
    if not settings.zap_url:
        return _zap_local_status(settings)
    version = await ZapClient(settings.zap_url, secrets.get(ZAP_API_KEY), timeout_s=5).version()
    if version is None:
        return IntegrationStatus("OWASP ZAP", False, f"تعذّر الاتصال بـ {settings.zap_url} (أو مفتاح API خاطئ)")
    return IntegrationStatus("OWASP ZAP", True, f"متصل — الإصدار {version}")
