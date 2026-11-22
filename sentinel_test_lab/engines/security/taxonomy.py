"""Maps findings to CWE / OWASP Top 10 (2021) and derives an overall posture score.

The score is a transparent index computed from the findings of one run. It is
not a certification and says nothing about checks that were not performed.
"""

from __future__ import annotations

from typing import Any

from ...core.models import Finding, Severity

OWASP = {
    "A01": "A01:2021 Broken Access Control",
    "A02": "A02:2021 Cryptographic Failures",
    "A03": "A03:2021 Injection",
    "A04": "A04:2021 Insecure Design",
    "A05": "A05:2021 Security Misconfiguration",
    "A06": "A06:2021 Vulnerable and Outdated Components",
    "A07": "A07:2021 Identification and Authentication Failures",
    "A08": "A08:2021 Software and Data Integrity Failures",
}

# (text that must appear in the title, CWE, OWASP key) — first match wins.
TITLE_RULES: tuple[tuple[str, str, str], ...] = (
    ("Strict-Transport-Security", "CWE-319", "A02"),
    ("HSTS", "CWE-319", "A02"),
    ("Content-Security-Policy", "CWE-693", "A05"),
    ("CSP", "CWE-693", "A05"),
    ("X-Frame-Options", "CWE-1021", "A05"),
    ("X-Content-Type-Options", "CWE-693", "A05"),
    ("Referrer-Policy", "CWE-200", "A05"),
    ("Permissions-Policy", "CWE-693", "A05"),
    ("DEBUG", "CWE-489", "A05"),
    ("stack trace", "CWE-209", "A05"),
    (".git", "CWE-538", "A05"),
    (".env", "CWE-538", "A05"),
    ("Directory listing", "CWE-548", "A05"),
    ("CORS", "CWE-942", "A05"),
    ("HttpOnly", "CWE-1004", "A05"),
    ("SameSite", "CWE-1275", "A01"),
)
CATEGORY_RULES: dict[str, tuple[str, str]] = {
    "information-disclosure": ("CWE-200", "A05"),
    "cookies": ("CWE-614", "A05"),
    "tls": ("CWE-326", "A02"),
}

WEIGHTS = {Severity.HIGH: 20, Severity.MEDIUM: 8, Severity.LOW: 3, Severity.INFO: 0}
GRADES = ((90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F"))


def classify(finding: Finding) -> Finding:
    """Fill in missing CWE / OWASP references in place."""
    if not finding.cwe or not finding.owasp:
        cwe = owasp = ""
        for needle, rule_cwe, rule_owasp in TITLE_RULES:
            if needle in finding.title:
                cwe, owasp = rule_cwe, rule_owasp
                break
        else:
            cwe, owasp = CATEGORY_RULES.get(finding.category, ("", ""))
        finding.cwe = finding.cwe or cwe
        finding.owasp = finding.owasp or OWASP.get(owasp, "")
    elif finding.owasp in OWASP:
        finding.owasp = OWASP[finding.owasp]
    return finding


def posture_score(findings: list[Finding]) -> dict[str, Any]:
    counts = {sev.value: sum(1 for f in findings if f.severity == sev) for sev in Severity}
    penalty = sum(WEIGHTS[f.severity] for f in findings)
    score = max(0, 100 - penalty)
    grade = next(letter for floor, letter in GRADES if score >= floor)
    if counts["high"] and grade in ("A", "B"):
        grade = "C"  # a high-severity finding never earns a top grade
    by_owasp: dict[str, int] = {}
    for f in findings:
        if f.owasp and f.severity != Severity.INFO:
            by_owasp[f.owasp] = by_owasp.get(f.owasp, 0) + 1
    return {
        "score": score, "grade": grade, "counts": counts,
        "by_owasp": dict(sorted(by_owasp.items())),
        "formula": "100 − (20 × عالية + 8 × متوسطة + 3 × منخفضة)",
    }
