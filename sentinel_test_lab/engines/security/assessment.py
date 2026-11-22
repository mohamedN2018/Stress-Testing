"""Security vulnerability assessment: passive by default.

Checks security headers, TLS, cookie attributes, information disclosure and
basic misconfiguration indicators, plus OWASP ZAP passive findings when a ZAP
daemon is configured. Nothing is exploited; no data is extracted or modified.
"""

from __future__ import annotations

from typing import Any

from ...core.authorization import ScopeError
from ...core.models import EngineOutcome, Finding, Severity
from ...integrations.zap.client import ZapClient, ZapError
from ...integrations.zap.daemon import local_daemon
from ..base import EngineContext
from ..http_runner import ScopedHttp
from .cookies import analyze_cookies
from .headers import analyze_security_headers
from .misconfig import assess_misconfiguration
from .tls import assess_tls


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.category, finding.title)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return sorted(unique, key=lambda f: -f.severity.rank)


class SecurityAssessmentEngine:
    async def run(self, ctx: EngineContext) -> EngineOutcome:
        target, config = ctx.target, ctx.config
        is_https = target.scheme == "https"
        findings: list[Finding] = []
        details: dict[str, Any] = {"pages": [], "zap": {"status": "غير مُعدّ"}}

        async with ctx.new_client(max_connections=2) as client:
            http = ScopedHttp(ctx, client)
            for path in config.paths or ["/"]:
                if ctx.guard.stopped:
                    break
                try:
                    response = await http.request("GET", path)
                except ScopeError as exc:
                    details["pages"].append({"path": path, "error": str(exc)})
                    continue
                if response is None:
                    details["pages"].append({"path": path, "error": "لا يوجد رد"})
                    continue
                cookies = response.headers.get_list("set-cookie")
                details["pages"].append({
                    "path": path, "status": response.status_code,
                    "headers": dict(response.headers), "cookies": len(cookies),
                })
                findings += analyze_security_headers(dict(response.headers), is_https)
                findings += analyze_cookies(cookies, is_https)
            ctx.emit("فحص الترويسات والكوكيز اكتمل؛ جارٍ فحص مؤشرات الإعدادات الخاطئة")
            if not ctx.guard.stopped:
                misconfig_findings, checks = await assess_misconfiguration(http)
                findings += misconfig_findings
                details["misconfiguration_checks"] = checks

        if not ctx.guard.stopped:
            ctx.emit("فحص إعدادات TLS")
            tls_findings, tls_details = await assess_tls(target)
            findings += tls_findings
            details["tls"] = tls_details

        if not ctx.guard.stopped:
            zap_findings, details["zap"] = await self._run_zap(ctx)
            findings += zap_findings

        return EngineOutcome(findings=_dedupe(findings), details=details)

    async def _run_zap(self, ctx: EngineContext) -> tuple[list[Finding], dict[str, Any]]:
        config, target = ctx.config, ctx.target
        if not config.extra.get("use_zap"):
            return [], {"status": "لم يُطلب"}
        daemon = local_daemon()
        if daemon.running:  # ZAP started by this application (random key, loopback only)
            zap_url, api_key, source = daemon.url, daemon.api_key, "local-daemon"
        elif ctx.settings.zap_url:
            zap_url, api_key, source = ctx.settings.zap_url, ctx.secrets.get("zap_api_key", ""), "configured"
        else:
            return [], {"status": "غير متاح: ZAP غير مشغَّل ولم يُحدَّد عنوانه في الإعدادات"}
        zap = ZapClient(zap_url, api_key)
        version = await zap.version()
        if version is None:
            return [], {"status": f"غير متاح: تعذّر الاتصال بـ ZAP على {zap_url}"}
        urls = [target.base_url + path for path in (config.paths or ["/"])]
        info: dict[str, Any] = {"status": "تم", "version": version, "mode": "passive", "source": source}
        try:
            if config.extra.get("active_scan"):
                info["mode"] = "active"
                ctx.emit("بدء فحص ZAP النشط (مصرّح به صراحةً) على المسارات المحددة فقط")
                delay_ms = int(1000 / max(config.rate_limit_rps, 0.1))
                findings = await zap.active_scan(
                    urls, target.base_url, lambda: ctx.guard.stopped, config.duration_s, delay_ms
                )
            else:
                ctx.emit("تشغيل فحص ZAP السلبي (Passive)")
                findings = await zap.passive_scan(urls, target.base_url, lambda: ctx.guard.stopped)
        except ZapError as exc:
            return [Finding(Severity.INFO, "zap", "تعذّر إكمال فحص ZAP", str(exc))], {
                "status": f"خطأ: {exc}", "version": version}
        info["alerts"] = len(findings)
        return findings, info
