"""HTML analysis, taxonomy and posture score: pure functions, no network."""

from __future__ import annotations

from sentinel_test_lab.core.models import Finding, Severity
from sentinel_test_lab.engines.security.taxonomy import classify, posture_score
from sentinel_test_lab.engines.security.webapp import analyze_html

CLEAN = """<html><head><script src="/static/app.js"></script>
<script src="https://cdn.example/lib.js" integrity="sha384-abc" crossorigin="anonymous"></script></head>
<body><form method="post"><input type="hidden" name="csrfmiddlewaretoken" value="x">
<input name="username"><input type="password" name="password"></form>
<form method="get" action="/search"><input name="q"></form></body></html>"""


def test_clean_page_has_no_findings():
    assert analyze_html(CLEAN, True, "site.example") == []


def test_post_form_without_csrf_token():
    html = '<form method="POST" action="/pay"><input name="amount"></form>'
    (finding,) = analyze_html(html, True, "site.example", "/pay")
    assert finding.cwe == "CWE-352" and finding.severity == Severity.MEDIUM and "/pay" in finding.evidence


def test_password_form_over_http_is_high():
    html = '<form method="post"><input name="csrf_token"><input type="password" name="p"></form>'
    assert analyze_html(html, True, "site.example") == []
    (finding,) = analyze_html(html, False, "site.example")
    assert finding.severity == Severity.HIGH and finding.cwe == "CWE-319"
    downgraded = html.replace('method="post"', 'method="post" action="http://site.example/login"')
    assert [f.cwe for f in analyze_html(downgraded, True, "site.example")] == ["CWE-319"]


def test_mixed_content_and_missing_sri():
    html = ('<script src="http://site.example/a.js"></script>'
            '<script src="https://other.example/b.js"></script>'
            '<script src="//site.example/c.js"></script>')
    cwes = {f.cwe for f in analyze_html(html, True, "site.example")}
    assert cwes == {"CWE-311", "CWE-353"}
    assert "CWE-311" not in {f.cwe for f in analyze_html(html, False, "site.example")}


def test_outdated_libraries_detected_from_script_url():
    html = ('<script src="/static/jquery-1.12.4.min.js"></script>'
            '<script src="/static/jquery-3.7.1.min.js"></script>'
            '<script src="https://cdn.example/bootstrap@3.3.7/js/bootstrap.min.js" integrity="x"></script>')
    titles = [f.title for f in analyze_html(html, True, "site.example") if f.category == "components"]
    assert titles == ["مكتبة jQuery قديمة (1.12.4)", "مكتبة Bootstrap قديمة (3.3.7)"]


def test_secrets_are_reported_masked_never_in_full():
    key = "AKIAIOSFODNN7EXAMPLE"
    html = f'<script>var k="{key}"; var SECRET_KEY = "django-insecure-abcdefgh";</script><p>10.0.4.12</p>'
    findings = analyze_html(html, True, "site.example", "/app")
    assert {f.cwe for f in findings} == {"CWE-798", "CWE-200"}
    assert all(key not in f.evidence and "django-insecure" not in f.evidence for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings)


def test_suspicious_comments():
    findings = analyze_html("<!-- TODO remove admin password --><p>hi</p><!-- layout -->", True, "s.example")
    assert [f.cwe for f in findings] == ["CWE-615"]


def test_malformed_html_never_raises():
    assert isinstance(analyze_html("<form <<< method=post <input", True, "s.example"), list)


def test_classify_fills_cwe_and_owasp():
    hsts = classify(Finding(Severity.MEDIUM, "headers", "ترويسة Strict-Transport-Security غير موجودة"))
    assert hsts.cwe == "CWE-319" and hsts.owasp.startswith("A02:2021")
    tls = classify(Finding(Severity.HIGH, "tls", "شهادة TLS منتهية الصلاحية"))
    assert tls.cwe == "CWE-326"
    explicit = classify(Finding(Severity.HIGH, "injection", "x", cwe="CWE-89", owasp="A03"))
    assert explicit.owasp == "A03:2021 Injection"
    unknown = classify(Finding(Severity.INFO, "misc", "ملاحظة"))
    assert unknown.cwe == "" and unknown.owasp == ""


def test_posture_score_and_grade():
    assert posture_score([])["grade"] == "A" and posture_score([])["score"] == 100
    one_high = posture_score([Finding(Severity.HIGH, "x", "a")])
    assert one_high["score"] == 80 and one_high["grade"] == "C"   # a high finding caps the grade
    many = posture_score([Finding(Severity.HIGH, "x", str(i)) for i in range(9)])
    assert many["score"] == 0 and many["grade"] == "F"
    info_only = posture_score([Finding(Severity.INFO, "x", "a", owasp="A05:2021 Security Misconfiguration")])
    assert info_only["score"] == 100 and info_only["by_owasp"] == {}


def test_finding_from_dict_accepts_old_and_future_records():
    old = Finding.from_dict({"severity": "low", "category": "c", "title": "t"})
    assert old.cwe == "" and old.owasp == ""
    assert Finding.from_dict({**old.to_dict(), "unknown_field": 1}).title == "t"
