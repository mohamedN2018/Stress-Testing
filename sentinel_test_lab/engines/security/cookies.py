"""Passive analysis of Set-Cookie attributes."""

from __future__ import annotations

import re

from ...core.models import Finding, Severity

SESSION_LIKE = re.compile(r"sess|sid|auth|token|csrf|jwt|login", re.IGNORECASE)


def parse_set_cookie(raw: str) -> tuple[str, set[str], str]:
    """Return (name, lower-cased attribute names, SameSite value)."""
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs: set[str] = set()
    samesite = ""
    for part in parts[1:]:
        key, _, value = part.partition("=")
        key = key.strip().lower()
        attrs.add(key)
        if key == "samesite":
            samesite = value.strip().lower()
    return name, attrs, samesite


def analyze_cookies(set_cookie_headers: list[str], is_https: bool) -> list[Finding]:
    findings: list[Finding] = []
    for raw in set_cookie_headers:
        name, attrs, samesite = parse_set_cookie(raw)
        if not name:
            continue
        sensitive = bool(SESSION_LIKE.search(name))
        problems: list[str] = []
        if is_https and "secure" not in attrs:
            problems.append("بدون Secure")
        # CSRF cookies are often readable by JS on purpose; do not flag HttpOnly for them.
        if "httponly" not in attrs and not re.search("csrf|xsrf", name, re.IGNORECASE):
            problems.append("بدون HttpOnly")
        if not samesite:
            problems.append("بدون SameSite")
        elif samesite == "none" and "secure" not in attrs:
            problems.append("SameSite=None بدون Secure")
        if problems:
            findings.append(Finding(
                Severity.MEDIUM if sensitive else Severity.LOW,
                "cookies",
                f"الكوكي «{name}»: {'، '.join(problems)}",
                "خصائص الكوكي الناقصة تسهّل سرقتها أو إساءة استخدامها (XSS/CSRF/اعتراض).",
                "عيّن Secure و HttpOnly و SameSite=Lax (أو Strict) لكوكيز الجلسات.",
                name,
            ))
    return findings
