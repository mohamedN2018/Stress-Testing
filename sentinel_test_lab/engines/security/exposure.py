"""Exposure checks: files and panels that should not be publicly reachable.

Read-only GET requests, one per item, all inside the authorized scope and the
run's rate limit. Only a short signature at the start of each response is
inspected; no file content is stored or reported.
"""

from __future__ import annotations

from typing import Any

from ...core.authorization import ScopeError
from ...core.models import Finding, Severity
from ..http_runner import ScopedHttp

# (path, signatures — any must appear in the first bytes, Arabic title)
SENSITIVE_FILES: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("/.git/config", ("[core]",), "إعدادات ‎.git مكشوفة (الشيفرة المصدرية قابلة للتنزيل)"),
    ("/.svn/entries", ("dir", "svn"), "مجلد ‎.svn مكشوف"),
    ("/.DS_Store", ("Bud1",), "ملف ‎.DS_Store مكشوف (يسرّب أسماء الملفات)"),
    ("/.htpasswd", (":$apr1$", ":$2y$", ":{SHA}"), "ملف ‎.htpasswd مكشوف"),
    ("/.aws/credentials", ("aws_access_key_id",), "بيانات اعتماد AWS مكشوفة"),
    ("/id_rsa", ("PRIVATE KEY",), "مفتاح SSH خاص مكشوف"),
    ("/db.sqlite3", ("SQLite format 3",), "قاعدة بيانات SQLite قابلة للتنزيل"),
    ("/backup.sql", ("CREATE TABLE", "INSERT INTO", "-- MySQL dump", "PostgreSQL database dump"),
     "نسخة احتياطية لقاعدة البيانات مكشوفة"),
    ("/dump.sql", ("CREATE TABLE", "INSERT INTO", "-- MySQL dump", "PostgreSQL database dump"),
     "نسخة احتياطية لقاعدة البيانات مكشوفة"),
    ("/docker-compose.yml", ("services:",), "ملف docker-compose.yml مكشوف"),
    ("/Dockerfile", ("FROM ",), "ملف Dockerfile مكشوف"),
    ("/settings.py", ("SECRET_KEY", "INSTALLED_APPS"), "ملف إعدادات Django مكشوف"),
    ("/wp-config.php.bak", ("DB_PASSWORD",), "نسخة من wp-config مكشوفة"),
    ("/config.php.bak", ("<?php",), "نسخة احتياطية لملف إعدادات PHP مكشوفة"),
    ("/phpinfo.php", ("phpinfo()", "PHP Version"), "صفحة phpinfo مكشوفة"),
    ("/server-status", ("Apache Server Status",), "صفحة Apache server-status مكشوفة"),
    ("/debug.log", ("Traceback", "ERROR", "PHP Warning", "PHP Fatal"), "ملف سجل أخطاء مكشوف"),
)
BINARY_OK = {"/.DS_Store", "/db.sqlite3"}

# (path, signatures, title, severity, recommendation)
PANELS: tuple[tuple[str, tuple[str, ...], str, Severity, str], ...] = (
    ("/admin/", ("Django administration", "Django site admin", "id_username"),
     "لوحة إدارة Django متاحة للعموم على المسار الافتراضي", Severity.LOW,
     "غيّر مسار ‎/admin/‎، وقيّده بعناوين IP موثوقة أو VPN، وفعّل المصادقة الثنائية."),
    ("/phpmyadmin/", ("phpMyAdmin",), "واجهة phpMyAdmin متاحة للعموم", Severity.MEDIUM,
     "احجب phpMyAdmin عن الإنترنت أو قيّده بعناوين IP موثوقة."),
    ("/wp-login.php", ("wp-submit", "user_login"), "صفحة دخول WordPress متاحة للعموم", Severity.INFO,
     "قيّد محاولات الدخول وفعّل المصادقة الثنائية."),
    ("/swagger/", ("swagger-ui", "Swagger UI"), "توثيق API (Swagger) متاح للعموم", Severity.LOW,
     "اجعل توثيق الـ API خلف مصادقة إن لم يكن الـ API عاماً."),
    ("/api/docs", ("swagger-ui", "Swagger UI", "redoc"), "توثيق API متاح للعموم", Severity.LOW,
     "اجعل توثيق الـ API خلف مصادقة إن لم يكن الـ API عاماً."),
    ("/openapi.json", ('"openapi"', '"swagger"'), "مخطط OpenAPI متاح للعموم", Severity.LOW,
     "اجعل مخطط الـ API خلف مصادقة إن لم يكن الـ API عاماً."),
    ("/actuator/env", ("propertySources",), "Spring Actuator يكشف متغيرات البيئة", Severity.HIGH,
     "عطّل نقاط Actuator الحساسة أو احمِها بمصادقة."),
)


async def assess_exposure(http: ScopedHttp, soft_404: bool,
                          stopped: Any = lambda: False) -> tuple[list[Finding], dict[str, Any]]:
    """``checks`` maps each path to True (exposed), False (not exposed) or None (not checked)."""
    findings: list[Finding] = []
    checks: dict[str, Any] = {}

    async def fetch(path: str) -> Any:
        if stopped():
            return None
        try:
            return await http.request("GET", path)
        except ScopeError:
            return None

    for path, signatures, title in SENSITIVE_FILES:
        response = await fetch(path)
        if response is None:
            checks[path] = None
            continue
        exposed = False
        if response.status_code == 200 and not soft_404:
            head = response.content[:400].decode("latin-1")
            is_html = "html" in response.headers.get("content-type", "").lower() or "<html" in head.lower()
            exposed = any(s in head for s in signatures) and (not is_html or path == "/phpinfo.php"
                                                              or path == "/server-status")
        checks[path] = exposed
        if exposed:
            findings.append(Finding(
                Severity.HIGH, "exposure", title,
                "ملف حساس متاح للتنزيل لأي زائر.",
                "احذفه من مجلد الويب أو امنع الوصول إليه من إعدادات الخادم، وغيّر أي أسرار وردت فيه.",
                path, "CWE-538", "A05"))

    for path, signatures, title, severity, fix in PANELS:
        response = await fetch(path)
        if response is None:
            checks[path] = None
            continue
        body = response.text[:20000] if response.status_code == 200 else ""
        exposed = bool(body) and not soft_404 and any(s in body for s in signatures)
        checks[path] = exposed
        if exposed:
            findings.append(Finding(severity, "exposure", title, "", fix, path, "CWE-200", "A05"))
    return findings, checks
