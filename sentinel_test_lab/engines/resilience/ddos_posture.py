"""DDoS *resilience posture* assessment (defensive, no traffic generation).

Looks at publicly observable protection indicators (CDN/WAF fingerprints,
Cloudflare edge addresses, caching behaviour, origin exposure hints in DNS) and,
when the user supplies a read-only Cloudflare API token, at the zone's
protection settings. It produces recommendations; it can never prove that a
site is "DDoS-proof".
"""

from __future__ import annotations

import ipaddress
from typing import Any

from ...core.authorization import ScopeError, classify_ip
from ...core.dns_lookup import lookup
from ...core.models import EngineOutcome, Finding, Severity
from ...integrations.cloudflare.client import CloudflareClient, CloudflareError, is_cloudflare_ip
from ..base import EngineContext
from ..http_runner import ScopedHttp
from .flood import RATE_LIMIT_HEADERS

DISCLAIMER = (
    "هذا تقييم لمؤشرات الحماية الظاهرة فقط. لا يمكن لأي فحص صغير أن يثبت أن الموقع محصَّن ضد هجمات DDoS."
)

# header (lower-case) -> (provider, substring that must appear in the value or "" for presence)
CDN_SIGNATURES: list[tuple[str, str, str]] = [
    ("cf-ray", "", "Cloudflare"), ("server", "cloudflare", "Cloudflare"),
    ("x-amz-cf-id", "", "Amazon CloudFront"), ("via", "cloudfront", "Amazon CloudFront"),
    ("x-served-by", "cache-", "Fastly"), ("x-fastly-request-id", "", "Fastly"),
    ("server", "akamaighost", "Akamai"), ("x-akamai-transformed", "", "Akamai"),
    ("x-sucuri-id", "", "Sucuri"), ("x-iinfo", "", "Imperva"), ("x-cdn", "incapsula", "Imperva"),
    ("x-azure-ref", "", "Azure Front Door"), ("x-vercel-id", "", "Vercel"),
    ("x-nf-request-id", "", "Netlify"), ("server", "bunnycdn", "Bunny CDN"),
    ("x-cache", "", "CDN/Cache (غير محدد)"),
]
ORIGIN_HINT_SUBDOMAINS = ("origin", "direct", "cpanel", "ftp", "mail", "webmail", "dev", "staging")


def detect_cdn(headers: dict[str, str]) -> list[str]:
    h = {k.lower(): v.lower() for k, v in headers.items()}
    found: list[str] = []
    for name, needle, provider in CDN_SIGNATURES:
        if name in h and needle in h[name] and provider not in found:
            found.append(provider)
    specific = [p for p in found if "غير محدد" not in p]
    return specific or found


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


async def _dns_records(name: str, record_type: str) -> list[str]:
    return await lookup(name, record_type)


class DdosPostureEngine:
    async def run(self, ctx: EngineContext) -> EngineOutcome:
        target = ctx.target
        findings: list[Finding] = []
        details: dict[str, Any] = {"disclaimer": DISCLAIMER, "cloudflare_api": {"status": "غير مُعدّ"}}

        # 1) Observable HTTP behaviour (two in-scope requests)
        headers: dict[str, str] = {}
        async with ctx.new_client(max_connections=2) as client:
            http = ScopedHttp(ctx, client)
            path = (ctx.config.paths or ["/"])[0]
            try:
                first = await http.request("GET", path)
                second = await http.request("GET", path) if first is not None else None
            except ScopeError as exc:
                findings.append(Finding(Severity.INFO, "scope", "المسار خارج النطاق المصرّح", str(exc)))
                return EngineOutcome(findings, details)
        if first is None:
            findings.append(Finding(Severity.INFO, "availability", "تعذّر الوصول إلى الهدف", ""))
            return EngineOutcome(findings, details)
        headers = dict(first.headers)
        providers = detect_cdn(headers)
        cache_headers = {
            k: v for k, v in (second or first).headers.items()
            if k.lower() in ("cache-control", "age", "cf-cache-status", "x-cache", "expires", "vary")
        }
        rate_headers = {k: v for k, v in headers.items() if k.lower() in RATE_LIMIT_HEADERS}
        details.update({
            "status_code": first.status_code, "cdn_providers": providers,
            "cache_headers": cache_headers, "rate_limit_headers": rate_headers,
        })

        # 2) Network placement
        edge_ips = [ip for ip in target.pinned_ips if is_cloudflare_ip(ip)]
        details["resolved_ips"] = target.pinned_ips
        details["cloudflare_edge_ips"] = edge_ips
        behind_cloudflare = bool(edge_ips) or "Cloudflare" in providers
        behind_cdn = behind_cloudflare or bool(providers)

        if target.network_class != "public":
            details["network_note"] = "هدف محلي/خاص: فحوص DNS والـ CDN العامة غير منطبقة."
            findings.append(Finding(
                Severity.INFO, "ddos", "هدف محلي/خاص",
                "مؤشرات الحماية على الحافة (CDN/WAF) تُقيَّم على النطاق العام للإنتاج فقط."))
        else:
            if behind_cdn:
                findings.append(Finding(
                    Severity.INFO, "ddos", f"الموقع خلف CDN/حماية حافة: {', '.join(providers) or 'Cloudflare'}",
                    "وجود CDN يمتص جزءاً كبيراً من هجمات الطبقة 3/4 والطلبات الثابتة."))
            else:
                findings.append(Finding(
                    Severity.HIGH, "ddos", "لم يُرصد CDN أو خدمة حماية أمام الموقع",
                    f"عناوين الـ IP ({', '.join(target.pinned_ips)}) تبدو عناوين الخادم الأصلي مباشرةً.",
                    "ضع الموقع خلف CDN/WAF (مثل Cloudflare) وقيّد الوصول للخادم الأصلي على عناوين الـ CDN فقط."))
            await self._dns_checks(ctx, behind_cdn, findings, details)

        # 3) Caching and rate limiting
        cache_control = cache_headers.get("cache-control", cache_headers.get("Cache-Control", "")).lower()
        cached = any(k.lower() in ("age", "cf-cache-status", "x-cache") for k in cache_headers) or (
            "max-age" in cache_control and "no-store" not in cache_control)
        details["caching_observed"] = cached
        if not cached:
            findings.append(Finding(
                Severity.LOW, "ddos", "لم يُرصد كاش للصفحة المختبَرة",
                "كل طلب يصل إلى التطبيق مباشرةً، ما يسهّل استنزاف الخادم بطلبات قليلة نسبياً.",
                "فعّل الكاش للصفحات العامة والملفات الثابتة على الـ CDN أو الخادم."))
        if not rate_headers:
            findings.append(Finding(
                Severity.INFO, "ddos", "لا توجد ترويسات تحديد معدل في الرد العادي",
                "قد يكون تحديد المعدل مفعّلاً دون إعلان؛ استخدم «تقييم مقاومة HTTP Flood» للتحقق عملياً."))

        # 4) Cloudflare zone settings (only with a user-supplied token)
        token = ctx.secrets.get("cloudflare_token", "")
        if token and target.network_class == "public" and not _is_ip(target.host):
            await self._cloudflare_api(ctx, token, findings, details)
        elif token:
            details["cloudflare_api"] = {"status": "غير منطبق على هذا الهدف"}

        findings.append(Finding(Severity.INFO, "ddos", "حدود هذا التقييم", DISCLAIMER))
        return EngineOutcome(findings, details)

    async def _dns_checks(
        self, ctx: EngineContext, behind_cdn: bool, findings: list[Finding], details: dict[str, Any]
    ) -> None:
        host = ctx.target.host
        if _is_ip(host):
            details["dns_note"] = "الهدف عنوان IP: فحوص DNS غير منطبقة."
            return
        apex = host[4:] if host.startswith("www.") else host
        nameservers = await _dns_records(apex, "NS")
        details["nameservers"] = nameservers
        exposed: list[dict[str, str]] = []
        if behind_cdn:
            for sub in ORIGIN_HINT_SUBDOMAINS:
                if ctx.guard.stopped:
                    break
                name = f"{sub}.{apex}"
                for ip in await _dns_records(name, "A"):
                    if classify_ip(ip) == "public" and not is_cloudflare_ip(ip) and ip not in ctx.target.pinned_ips:
                        exposed.append({"name": name, "ip": ip})
            for record in await _dns_records(apex, "MX"):
                mx_host = record.split()[-1]
                if mx_host.endswith(apex):
                    for ip in await _dns_records(mx_host, "A"):
                        if classify_ip(ip) == "public" and not is_cloudflare_ip(ip):
                            exposed.append({"name": mx_host, "ip": ip})
        details["origin_exposure_indicators"] = exposed
        if exposed:
            names = "، ".join(sorted({e["name"] for e in exposed}))
            findings.append(Finding(
                Severity.MEDIUM, "ddos", "مؤشرات على انكشاف عنوان الخادم الأصلي عبر DNS",
                f"سجلات فرعية تشير إلى عناوين خارج شبكة الـ CDN: {names}. "
                "إن كانت على نفس الخادم الأصلي فيمكن تجاوز الـ CDN ومهاجمته مباشرةً.",
                "انقل البريد والخدمات الأخرى لعناوين مختلفة، وقيّد جدار الخادم الأصلي على نطاقات الـ CDN فقط.",
                ", ".join(f"{e['name']}={e['ip']}" for e in exposed)[:300]))

    async def _cloudflare_api(
        self, ctx: EngineContext, token: str, findings: list[Finding], details: dict[str, Any]
    ) -> None:
        client = CloudflareClient(token, ctx.settings.cloudflare_api_base)
        try:
            posture = await client.zone_posture(ctx.target.host)
        except CloudflareError as exc:
            details["cloudflare_api"] = {"status": f"خطأ: {exc}"}
            return
        details["cloudflare_api"] = {"status": "تم", **posture}
        settings = posture["settings"]
        level = settings.get("security_level")
        if level in ("off", "essentially_off", "low"):
            findings.append(Finding(
                Severity.MEDIUM, "ddos", f"Cloudflare Security Level منخفض ({level})",
                "", "ارفعه إلى Medium على الأقل، واستخدم Under Attack Mode عند الهجوم."))
        if settings.get("always_use_https") == "off":
            findings.append(Finding(Severity.LOW, "ddos", "Always Use HTTPS معطّل في Cloudflare", "",
                                    "فعّله من SSL/TLS → Edge Certificates."))
        if settings.get("ssl") == "flexible":
            findings.append(Finding(
                Severity.MEDIUM, "tls", "وضع SSL في Cloudflare هو Flexible",
                "الاتصال بين Cloudflare والخادم الأصلي غير مشفَّر.", "استخدم Full (strict)."))
        phases = {r.get("phase") for r in posture["rulesets"]}
        if "http_ratelimit" not in phases:
            findings.append(Finding(
                Severity.MEDIUM, "ddos", "لا توجد قواعد Rate Limiting في Cloudflare",
                "", "أضف قاعدة Rate Limiting لمسارات الدخول والـ API والبحث."))
        if not phases & {"http_request_firewall_managed", "http_request_firewall_custom"} and settings.get("waf") != "on":
            findings.append(Finding(
                Severity.MEDIUM, "ddos", "لم تُرصد قواعد WAF مفعّلة في Cloudflare",
                "", "فعّل Managed Rules أو أضف قواعد WAF مخصصة."))
