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
from .exposure import assess_exposure
from .headers import analyze_security_headers
from .misconfig import assess_misconfiguration
from .probes import run_input_probes
from .taxonomy import classify, posture_score
from .tls import assess_tls
from .webapp import analyze_html


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.category, finding.title)
        if key not in seen:
            seen.add(key)
            unique.append(classify(finding))
    return sorted(unique, key=lambda f: -f.severity.rank)


def coverage(details: dict[str, Any], probes: bool) -> list[dict[str, str]]:
    """What this run actually checked, so an empty findings list is not over-read."""
    def counted(checks: dict[str, Any]) -> str:
        done = sum(1 for v in checks.values() if v is not None)
        return f"{done} من {len(checks)} فحصاً" + ("" if done == len(checks) else " (الباقي خارج النطاق)")

    pages = [p for p in details.get("pages", []) if "error" not in p]
    exposure = details.get("exposure_checks")
    zap = details.get("zap", {})
    tls = details.get("tls")
    rows = [
        ("ترويسات الأمان والكوكيز", f"{len(pages)} صفحة" if pages else "لم يُنفَّذ"),
        ("تحليل HTML: النماذج، CSRF، السكربتات، الأسرار، المكتبات", f"{len(pages)} صفحة" if pages else "لم يُنفَّذ"),
        ("صفحات الأخطاء، CORS، استعراض المجلدات",
         "تم" if "misconfiguration_checks" in details else "لم يُنفَّذ"),
        ("ملفات ولوحات مكشوفة", counted(exposure) if exposure else "لم يُنفَّذ"),
        ("TLS والشهادة", "تم" if tls else "لم يُنفَّذ"),
        ("معالجة المدخلات (XSS / SQL / Open Redirect)",
         f"{details['input_probes'].get('parameters_probed', 0)} معاملاً" if probes else "لم يُطلب"),
        ("OWASP ZAP", f"{zap.get('mode')} — {zap.get('alerts', 0)} تنبيهاً" if zap.get("status") == "تم"
         else str(zap.get("status", "لم يُطلب"))),
    ]
    return [{"check": name, "result": result} for name, result in rows]


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
                if "html" in response.headers.get("content-type", "").lower():
                    findings += analyze_html(response.text, is_https, target.host, path.partition("?")[0])
            ctx.emit("فحص الترويسات والكوكيز اكتمل؛ جارٍ فحص مؤشرات الإعدادات الخاطئة")
            if not ctx.guard.stopped:
                misconfig_findings, checks = await assess_misconfiguration(http)
                findings += misconfig_findings
                details["misconfiguration_checks"] = checks
            if not ctx.guard.stopped:
                ctx.emit("فحص الملفات واللوحات المكشوفة")
                exposure_findings, details["exposure_checks"] = await assess_exposure(
                    http, bool(details.get("misconfiguration_checks", {}).get("soft_404")),
                    lambda: ctx.guard.stopped)
                findings += exposure_findings
            if config.extra.get("input_probes") and not ctx.guard.stopped:
                ctx.emit("فحص معالجة المدخلات (كشف فقط، بقيم غير ضارة)")
                probe_findings, details["input_probes"] = await run_input_probes(
                    http, config.paths or ["/"], lambda: ctx.guard.stopped)
                findings += probe_findings
            else:
                details["input_probes"] = {"status": "لم يُطلب"}

        if not ctx.guard.stopped:
            ctx.emit("فحص إعدادات TLS")
            tls_findings, tls_details = await assess_tls(target)
            findings += tls_findings
            details["tls"] = tls_details

        if not ctx.guard.stopped:
            zap_findings, details["zap"] = await self._run_zap(ctx)
            findings += zap_findings

        unique = _dedupe(findings)
        details["posture"] = posture_score(unique)
        details["coverage"] = coverage(details, bool(config.extra.get("input_probes")))
        return EngineOutcome(findings=unique, details=details)

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
