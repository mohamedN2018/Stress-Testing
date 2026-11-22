"""Input-handling probes: detection only, with inert values.

Each probe sends one ordinary GET with a harmless marker in a query parameter
and looks at how the application answers. Nothing is exploited:

* reflection  — a random marker wrapped in ``"'<>``; never a script.
* SQL errors  — a single quote; only an error *message* is looked for.
* redirects   — an ``.example`` URL (reserved, unresolvable); redirects are never followed.

Requires a trusted target and explicit opt-in (enforced by SafetyManager).
"""

from __future__ import annotations

import re
import secrets
from typing import Any, Callable
from urllib.parse import parse_qsl, urlsplit

from ...core.authorization import ScopeError
from ...core.models import Finding, Severity
from ..http_runner import ScopedHttp

MAX_PARAMS = 6  # parameters probed per run, across all pages
REDIRECT_PARAMS = ("next", "url", "redirect", "redirect_to", "return", "return_to", "returnurl",
                   "continue", "dest", "destination", "goto", "target", "r", "u")
REDIRECT_PROBE = "https://sentinel-redirect-probe.example/"
SQL_ERRORS = re.compile(
    r"(?i)(you have an error in your sql syntax|warning: mysqli?[_:]|unclosed quotation mark"
    r"|quoted string not properly terminated|pg_query\(\)|psycopg2\.errors|syntax error at or near"
    r"|sqlite3\.OperationalError|SQLite/JDBCDriver|unrecognized token|ORA-\d{5}"
    r"|django\.db\.utils\.\w+Error|SQLSTATE\[)")


def split_path(path: str) -> tuple[str, list[tuple[str, str]]]:
    parts = urlsplit(path)
    return parts.path or "/", parse_qsl(parts.query, keep_blank_values=True)


async def run_input_probes(http: ScopedHttp, paths: list[str],
                           stopped: Callable[[], bool] = lambda: False
                           ) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    info: dict[str, Any] = {"parameters_probed": 0, "requests": 0, "skipped": []}
    if not any("?" in p for p in paths):
        info["note"] = "لا توجد معاملات في الصفحات المحددة؛ أضف صفحة بمعاملاتها مثل ‎/search?q=test"
    seen_titles: set[str] = set()

    async def get(path: str, params: list[tuple[str, str]]) -> Any:
        if stopped():
            return None
        try:
            response = await http.request("GET", path, params=params)
        except ScopeError:
            info["skipped"].append(path)
            return None
        if response is not None:
            info["requests"] += 1
        return response

    def add(finding: Finding) -> None:
        key = finding.title + finding.evidence
        if key not in seen_titles:
            seen_titles.add(key)
            findings.append(finding)

    for raw in paths:
        path, params = split_path(raw)
        for index, (name, value) in enumerate(params):
            if info["parameters_probed"] >= MAX_PARAMS or stopped():
                break
            info["parameters_probed"] += 1

            def mutated(new_value: str) -> list[tuple[str, str]]:
                return [(n, new_value if i == index else v) for i, (n, v) in enumerate(params)]

            # 1) reflection of unencoded markup characters
            marker = "stl" + secrets.token_hex(4)
            response = await get(path, mutated(f'{marker}"\'<>'))
            if response is not None and "html" in response.headers.get("content-type", "").lower():
                body = response.text[:300_000]
                if f'{marker}"\'<>' in body or f"{marker}\"'<" in body:
                    add(Finding(
                        Severity.HIGH, "injection", "انعكاس مدخلات بدون ترميز (مؤشر قوي على XSS)",
                        "قيمة المعامل تُطبع في الصفحة كما هي بما فيها < > والاقتباسات.",
                        "رمّز المخرجات حسب السياق (في Django: لا تستخدم |safe أو mark_safe مع مدخلات "
                        "المستخدم) وأضف Content-Security-Policy.",
                        f"{path} ← المعامل {name}", "CWE-79", "A03"))
            # 2) database error disclosure
            response = await get(path, mutated(value + "'"))
            if response is not None:
                match = SQL_ERRORS.search(response.text[:300_000])
                if match:
                    add(Finding(
                        Severity.HIGH, "injection", "رسالة خطأ قاعدة بيانات عند إدخال علامة اقتباس (مؤشر SQL Injection)",
                        "المدخل يصل إلى استعلام SQL دون معالجة، ورسالة الخطأ تُعرض للزائر.",
                        "استخدم استعلامات مُعلَّمة (parameterized) أو الـ ORM فقط، ولا تبنِ SQL بضم النصوص، "
                        "واعرض صفحات خطأ عامة.",
                        f"{path} ← المعامل {name} — {match.group(0)[:60]}", "CWE-89", "A03"))
            # 3) open redirect on redirect-like parameters
            if name.lower() in REDIRECT_PARAMS:
                response = await get(path, mutated(REDIRECT_PROBE))
                if response is not None and 300 <= response.status_code < 400 and \
                        response.headers.get("location", "").startswith(REDIRECT_PROBE):
                    add(Finding(
                        Severity.MEDIUM, "injection", "إعادة توجيه مفتوحة (Open Redirect)",
                        "الموقع يحوّل الزائر إلى أي عنوان خارجي يُمرَّر في المعامل (يُستغل في التصيّد).",
                        "اسمح بالتحويل إلى مسارات داخلية فقط (في Django: url_has_allowed_host_and_scheme).",
                        f"{path} ← المعامل {name}", "CWE-601", "A01"))
    return findings, info
