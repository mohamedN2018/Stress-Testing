"""Report model (shared by HTML and PDF) and the self-contained HTML report."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup

from .. import APP_NAME, __version__, resource_path
from ..core.i18n import (
    BACKEND_LABELS,
    NOT_AVAILABLE,
    PERFORMANCE_TYPES,
    SEVERITY_LABELS,
    STATUS_LABELS,
    TEST_TYPE_LABELS,
)
from ..core.models import RunRecord
from .charts import run_charts
from .recommendations import executive_summary

TEMPLATES = resource_path("reporting", "templates")
_env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=select_autoescape(["html", "j2"]))

CONFIG_LABELS = {
    "users": "المستخدمون الافتراضيون", "duration_s": "المدة (ث)", "ramp_up_s": "زمن التصعيد (ث)",
    "requests_per_user": "طلبات لكل مستخدم", "interval_s": "الفاصل بين الطلبات (ث)", "method": "الطريقة",
    "paths": "المسارات", "rate_limit_rps": "حد المعدل (طلب/ث)", "request_budget": "ميزانية الطلبات",
    "timeout_s": "مهلة الطلب (ث)",
}
EXTRA_LABELS = {
    "start_users": "مستخدمو البداية", "step_users": "زيادة كل مرحلة", "max_users": "أقصى مستخدمين",
    "step_duration_s": "مدة المرحلة (ث)", "baseline_users": "مستخدمو الخط الأساسي",
    "spike_users": "مستخدمو القفزة", "baseline_s": "مدة الخط الأساسي (ث)", "spike_s": "مدة القفزة (ث)",
    "recovery_s": "مدة التعافي (ث)", "login_path": "مسار الدخول", "attempts": "عدد المحاولات",
    "test_username": "حساب الاختبار", "mfa": "MFA (إدخال يدوي)", "use_zap": "فحص ZAP",
    "active_scan": "فحص نشط", "content_type": "نوع المحتوى",
    "input_probes": "فحص معالجة المدخلات", "header_names": "ترويسات مخصصة (الأسماء فقط)",
}
THRESHOLD_LABELS = {
    "max_error_rate": "أقصى نسبة أخطاء", "max_p95_ms": "أقصى p95 (ms)",
    "max_consecutive_failures": "أقصى إخفاقات متتالية",
}


def fmt(value: Any, unit: str = "", digits: int = 2) -> str:
    """Human formatting; missing measurements are labelled, never replaced by a number."""
    if value is None or value == "":
        return NOT_AVAILABLE
    if isinstance(value, bool):
        return "نعم" if value else "لا"
    if isinstance(value, float):
        value = round(value, digits)
        text = f"{value:,.{digits}f}".rstrip("0").rstrip(".")
    elif isinstance(value, int):
        text = f"{value:,}"
    elif isinstance(value, (list, tuple)):
        text = "، ".join(str(v) for v in value) or "—"
    else:
        text = str(value)
    return f"{text} {unit}".strip()


def pct(value: Any) -> str:
    return NOT_AVAILABLE if value is None else f"{value * 100:.1f}%"


def local_time(iso: str | None) -> str:
    if not iso:
        return NOT_AVAILABLE
    try:
        return datetime.fromisoformat(iso).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return iso


def _kv(title: str, pairs: list[tuple[str, Any]], note: str = "") -> dict[str, Any]:
    return {"title": title, "headers": ["البند", "القيمة"],
            "rows": [[k, v if isinstance(v, str) else fmt(v)] for k, v in pairs], "note": note}


def _phase_rows(phases: dict[str, dict[str, Any]]) -> list[list[str]]:
    return [[name, fmt(p.get("users")), fmt(p.get("total")), fmt(p.get("rps")), fmt(p.get("avg_ms")),
             fmt(p.get("p95_ms")), pct(p.get("error_rate"))] for name, p in phases.items()]


def detail_tables(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Engine-specific result tables."""
    d = record.get("details") or {}
    kind = record.get("test_type")
    tables: list[dict[str, Any]] = []
    phase_headers = ["المرحلة", "المستخدمون", "الطلبات", "RPS", "avg ms", "p95 ms", "نسبة الأخطاء"]
    if kind == "stress" and d.get("steps"):
        tables.append({
            "title": "مراحل اختبار الإجهاد",
            "headers": ["المستخدمون", "الطلبات", "RPS", "p95 ms", "نسبة الأخطاء", "النتيجة"],
            "rows": [[fmt(s.get("users")), fmt(s.get("total")), fmt(s.get("rps")), fmt(s.get("p95_ms")),
                      pct(s.get("error_rate")),
                      "ضمن العتبات" if s.get("passed") else "تجاوز: " + "، ".join(s.get("reasons") or [])]
                     for s in d["steps"]],
            "note": "«أعلى حمل مستدام» هو أعلى مستوى تم اختباره فعلياً وبقي ضمن العتبات، وليس السعة القصوى للخادم.",
        })
        tables.append(_kv("نتيجة اختبار الإجهاد", [
            ("أعلى حمل مستدام تم اختباره (مستخدم)", d.get("max_sustainable_users")),
            ("أول مستوى تجاوز العتبات (مستخدم)", d.get("first_failing_users")),
            ("أقصى حمل مخطط (مستخدم)", d.get("planned_max_users")),
            ("هل بُلغ حد الأداء؟", bool(d.get("limit_reached"))),
        ]))
    elif kind == "spike" and d.get("phases"):
        tables.append({"title": "مراحل اختبار القفزة", "headers": phase_headers,
                       "rows": _phase_rows(d["phases"]), "note": ""})
        recovered = d.get("recovered")
        tables.append(_kv("مقارنة قبل/بعد القفزة", [
            ("p95 أثناء القفزة ÷ قبلها", d.get("spike_vs_baseline_p95")),
            ("p95 بعد القفزة ÷ قبلها", d.get("recovery_vs_baseline_p95")),
            ("نسبة الأخطاء أثناء القفزة", pct(d.get("spike_error_rate"))),
            ("تعافى النظام؟", "لم يُقَس (انتهى التشغيل قبل مرحلة التعافي)" if recovered is None else recovered),
        ]))
    elif kind == "load" and d.get("phases"):
        tables.append({"title": "مراحل اختبار الحمل", "headers": phase_headers,
                       "rows": _phase_rows(d["phases"]), "note": ""})
    elif kind == "flood":
        tables.append(_kv("نتيجة تقييم مقاومة HTTP Flood", [
            ("المعدل المضبوط (طلب/ث)", d.get("configured_rps")), ("المعدل الفعلي (طلب/ث)", d.get("achieved_rps")),
            ("الطلبات المرسلة", d.get("requests_sent")), ("رُصد تحديد للمعدل؟", bool(d.get("rate_limited"))),
            ("عدد ردود 429", d.get("count_429")), ("أول 429 عند الطلب رقم", d.get("first_429_at_request")),
            ("Retry-After", d.get("retry_after")), ("عدد ردود 403", d.get("count_403")),
            ("عدد ردود 5xx", d.get("count_5xx")),
            ("ترويسات RateLimit", "، ".join(f"{k}: {v}" for k, v in (d.get("rate_limit_headers") or {}).items()) or "—"),
        ], "اختبار محدود من مصدر واحد: يرصد وجود تحديد المعدل ولا يقيس قدرة تحمل هجوم حقيقي."))
    elif kind == "brute_force":
        tables.append(_kv("نتيجة تقييم الحماية من Brute Force", [
            ("مسار الدخول", d.get("login_path")), ("المحاولات المخططة", d.get("attempts_planned")),
            ("رُصدت حماية؟", d.get("protection_detected")), ("نوع الحماية", d.get("trigger")),
            ("عند المحاولة رقم", d.get("trigger_attempt")), ("MFA (إدخال يدوي)", d.get("mfa_declared")),
        ], "استُخدم حساب اختبار مخصص وكلمات مرور عشوائية خاطئة فقط."))
        if d.get("attempts"):
            tables.append({"title": "المحاولات", "headers": ["#", "الحالة", "الزمن ms", "Retry-After"],
                           "rows": [[fmt(a.get("attempt")), fmt(a.get("status")), fmt(a.get("latency_ms")),
                                     fmt(a.get("retry_after"))] for a in d["attempts"]], "note": ""})
    elif kind == "security":
        posture = d.get("posture")
        if posture:
            counts = posture.get("counts") or {}
            tables.append(_kv("مؤشر الوضع الأمني", [
                ("التقدير", posture.get("grade")), ("الدرجة من 100", posture.get("score")),
                ("ملاحظات عالية / متوسطة / منخفضة",
                 f"{counts.get('high', 0)} / {counts.get('medium', 0)} / {counts.get('low', 0)}"),
                ("طريقة الحساب", posture.get("formula")),
            ]))
            tables[-1]["note"] = ("مؤشر تقريبي مبني على ملاحظات هذا التشغيل فقط؛ ليس شهادة أمان، "
                                  "ولا يغطي ما لم يُفحص.")
            if posture.get("by_owasp"):
                tables.append({"title": "الملاحظات حسب OWASP Top 10", "headers": ["الفئة", "العدد"],
                               "rows": [[k, fmt(v)] for k, v in posture["by_owasp"].items()], "note": ""})
        if d.get("coverage"):
            tables.append({"title": "ما تم فحصه في هذا التشغيل", "headers": ["الفحص", "النتيجة"],
                           "rows": [[c["check"], c["result"]] for c in d["coverage"]], "note": ""})
        if d.get("pages"):
            tables.append({"title": "الصفحات المفحوصة", "headers": ["المسار", "الحالة", "الكوكيز"],
                           "rows": [[p.get("path", ""), fmt(p.get("status")) if "status" in p else p.get("error", ""),
                                     fmt(p.get("cookies"))] for p in d["pages"]], "note": ""})
        tls = d.get("tls") or {}
        if tls:
            legacy = tls.get("legacy_protocols") or {}
            legacy_text = "، ".join(
                f"{k}: {'مقبول' if v else 'مرفوض' if v is False else 'تعذّر الفحص'}" for k, v in legacy.items())
            tables.append(_kv("TLS", [
                ("البروتوكول", tls.get("protocol")), ("الشيفرة", tls.get("cipher")),
                ("الشهادة لـ", tls.get("subject")), ("الجهة المصدرة", tls.get("issuer")),
                ("تنتهي في", tls.get("not_after")), ("الأيام المتبقية", tls.get("days_remaining")),
                ("موثوقة؟", tls.get("trusted")), ("بروتوكولات قديمة", legacy_text or tls.get("note")),
            ]))
        tables.append(_kv("OWASP ZAP", [
            ("الحالة", (d.get("zap") or {}).get("status")), ("الإصدار", (d.get("zap") or {}).get("version")),
            ("الوضع", (d.get("zap") or {}).get("mode")), ("عدد التنبيهات", (d.get("zap") or {}).get("alerts")),
        ]))
    elif kind == "ddos_posture":
        exposure = d.get("origin_exposure_indicators")
        cf = d.get("cloudflare_api") or {}
        tables.append(_kv("مؤشرات الحماية الظاهرة", [
            ("CDN / حماية الحافة", d.get("cdn_providers") or "لم يُرصد"),
            ("عناوين IP", d.get("resolved_ips")), ("عناوين ضمن شبكة Cloudflare", d.get("cloudflare_edge_ips") or "لا يوجد"),
            ("Nameservers", d.get("nameservers") if "nameservers" in d else None),
            ("كاش مرصود؟", d.get("caching_observed")),
            ("ترويسات الكاش", "، ".join(f"{k}: {v}" for k, v in (d.get("cache_headers") or {}).items()) or "—"),
            ("مؤشرات انكشاف الأصل", None if exposure is None else
             ("، ".join(f"{e['name']} ({e['ip']})" for e in exposure) or "لا يوجد")),
            ("Cloudflare API", cf.get("status")),
        ], d.get("disclaimer", "")))
        if cf.get("settings"):
            tables.append(_kv("إعدادات Cloudflare", list(cf["settings"].items())))
    # Host resource usage (always labelled with whose metrics they are)
    system = [s["system"] for s in record.get("series") or [] if s.get("system")]
    cpu = [s["cpu_percent"] for s in system if s.get("cpu_percent") is not None]
    ram = [s["ram_percent"] for s in system if s.get("ram_percent") is not None]
    scope = (record.get("summary") or {}).get("metrics_host_scope")
    if cpu or ram:
        note = ("الهدف يعمل على نفس الجهاز، فهذه القيم تشمل الخادم ومولّد الحمل معاً."
                if scope == "target_and_generator" else
                "هذه قيم جهاز مولّد الحمل فقط. مقاييس الخادم البعيد وقاعدة البيانات غير متاحة في هذا الإصدار.")
        tables.append(_kv("موارد الجهاز أثناء الاختبار", [
            ("أقصى CPU", fmt(max(cpu), "%") if cpu else None), ("متوسط CPU", fmt(sum(cpu) / len(cpu), "%") if cpu else None),
            ("أقصى RAM", fmt(max(ram), "%") if ram else None),
            ("مقاييس الخادم البعيد / قاعدة البيانات", NOT_AVAILABLE if scope != "target_and_generator" else "مشمولة أعلاه (نفس الجهاز)"),
        ], note))
    monitor = (record.get("summary") or {}).get("container_monitor")
    if monitor:
        samples = [s["container"] for s in record.get("series") or [] if s.get("container")]
        c_cpu = [s["cpu_percent"] for s in samples if s.get("cpu_percent") is not None]
        c_mem = [s["mem_used_mb"] for s in samples if s.get("mem_used_mb") is not None]
        limit = next((s["mem_limit_mb"] for s in samples if s.get("mem_limit_mb")), None)
        tables.append(_kv("موارد حاوية الخادم (Docker): " + str(monitor.get("container")), [
            ("الخادم", monitor.get("host")),
            ("أقصى CPU", fmt(max(c_cpu), "%") if c_cpu else None),
            ("متوسط CPU", fmt(sum(c_cpu) / len(c_cpu), "%") if c_cpu else None),
            ("أقصى ذاكرة", fmt(max(c_mem), "MB") if c_mem else None),
            ("حد الذاكرة", fmt(limit, "MB") if limit else None),
            ("عدد العينات", monitor.get("samples")),
            ("خطأ القراءة", monitor.get("error") or "لا يوجد"),
        ], "قيم docker stats للحاوية المحددة في الإعدادات. CPU قد يتجاوز 100% على خادم متعدد الأنوية."))
    return tables


def config_rows(config: dict[str, Any]) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for key, label in CONFIG_LABELS.items():
        if key not in config:
            continue
        if key == "users" and any(k in (config.get("extra") or {}) for k in ("max_users", "spike_users")):
            continue  # stress/spike define their own user levels below
        value = config[key]
        if key == "requests_per_user" and not value:
            rows.append((label, "غير محدد (محكوم بالمدة والميزانية)"))
        else:
            rows.append((label, fmt(value)))
    rows.append(("المحرك", BACKEND_LABELS.get(config.get("backend", "internal"), "")))
    for key, label in THRESHOLD_LABELS.items():
        value = (config.get("thresholds") or {}).get(key)
        if value is not None:
            rows.append((label, pct(value) if key == "max_error_rate" else fmt(value)))
    for key, value in (config.get("extra") or {}).items():
        if key.endswith("_confirmed") or key in ("username_field", "password_field", "csrf_field"):
            continue
        rows.append((EXTRA_LABELS.get(key, key), fmt(value)))
    return rows


def build_report_context(run: RunRecord) -> dict[str, Any]:
    record = run.to_dict()
    s = record["summary"]
    has_requests = bool(s.get("total"))
    cards = [
        ("إجمالي الطلبات", fmt(s.get("total"))), ("ناجحة", fmt(s.get("success"))),
        ("فاشلة", fmt(s.get("failed"))), ("نسبة الأخطاء", pct(s.get("error_rate"))),
        ("متوسط RPS", fmt(s.get("rps"))), ("أقصى RPS", fmt(s.get("peak_rps"))),
        ("متوسط الزمن", fmt(s.get("avg_ms"), "ms")), ("p50", fmt(s.get("p50_ms"), "ms")),
        ("p90", fmt(s.get("p90_ms"), "ms")), ("p95", fmt(s.get("p95_ms"), "ms")),
        ("p99", fmt(s.get("p99_ms"), "ms")), ("أقصى مستخدمين", fmt(s.get("peak_users"))),
        ("HTTP 2xx", fmt(s.get("s2xx"))), ("HTTP 3xx", fmt(s.get("s3xx"))),
        ("HTTP 4xx", fmt(s.get("s4xx"))), ("HTTP 5xx", fmt(s.get("s5xx"))),
    ]
    if record["test_type"] not in PERFORMANCE_TYPES:
        hidden = {"ناجحة", "فاشلة", "نسبة الأخطاء", "أقصى مستخدمين", "أقصى RPS", "متوسط RPS"}
        cards = [card for card in cards if card[0] not in hidden]
    if s.get("aborted"):
        cards.append(("أُلغيت أثناء الإرسال عند التوقف", fmt(s.get("aborted"))))
    sustainable = s.get("max_sustainable_tested_users")
    is_load = record["test_type"] in ("load", "stress", "spike")
    findings = sorted(record["findings"], key=lambda f: -{"info": 0, "low": 1, "medium": 2, "high": 3}[f["severity"]])
    for finding in findings:
        finding["severity_label"] = SEVERITY_LABELS[finding["severity"]]
    recommendations: list[str] = []
    for finding in findings:
        if finding["recommendation"] and finding["recommendation"] not in recommendations:
            recommendations.append(finding["recommendation"])
    limitations = [
        "النتائج تخص هذا التشغيل وحده، من مصدر واحد وبالحدود المذكورة في الإعدادات.",
        "لا يحدد هذا التقرير السعة القصوى الدقيقة للخادم ما لم يُذكر أن حد الأداء بُلغ فعلاً.",
        "أي قيمة معنونة «غير متاح» لم تُقَس ولم تُقدَّر.",
    ]
    if record["test_type"] in ("security", "brute_force", "ddos_posture", "flood"):
        limitations.append("التقييم دفاعي وغير اقتحامي؛ غياب الملاحظات لا يعني خلو الموقع من الثغرات.")
    charts = [(title, Markup(svg)) for title, svg in run_charts(record)]
    return {
        "app_name": APP_NAME, "version": __version__,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "name": record["name"], "target_url": record["target_url"],
        "type_label": TEST_TYPE_LABELS.get(record["test_type"], record["test_type"]),
        "status": record["status"], "status_label": STATUS_LABELS.get(record["status"], record["status"]),
        "stop_reason": record["stop_reason"],
        "started": local_time(record["started_at"]), "finished": local_time(record["finished_at"]),
        "duration": fmt(s.get("elapsed_s"), "ث"),
        "summary_lines": executive_summary(record),
        "cards": cards if has_requests else cards[:1],
        "sustainable": (fmt(sustainable, "مستخدم") if sustainable else "لم يثبته هذا الاختبار") if is_load else None,
        "config": config_rows(record["config"]),
        "charts": charts, "raw_charts": run_charts(record),
        "tables": detail_tables(record),
        "findings": findings, "recommendations": recommendations, "limitations": limitations,
        "run_id": record["id"],
    }


def render_html(run: RunRecord) -> str:
    return _env.get_template("report.html.j2").render(**build_report_context(run))


def write_html(run: RunRecord, path: Path) -> Path:
    path.write_text(render_html(run), encoding="utf-8")
    return path


def render_template(template_name: str, /, **context: Any) -> str:
    return _env.get_template(template_name).render(**context)
