from __future__ import annotations

from sentinel_test_lab.core.config import Thresholds
from sentinel_test_lab.core.models import Severity, TestType
from sentinel_test_lab.engines.resilience.bruteforce import extract_hidden_field
from sentinel_test_lab.engines.resilience.ddos_posture import detect_cdn
from sentinel_test_lab.engines.security.cookies import analyze_cookies, parse_set_cookie
from sentinel_test_lab.engines.security.headers import analyze_security_headers
from sentinel_test_lab.engines.stress.engine import build_steps
from sentinel_test_lab.core.models import TestConfig
from sentinel_test_lab.reporting.recommendations import (
    analyze_performance,
    executive_summary,
    max_sustainable_tested_users,
)

GOOD = {
    "Strict-Transport-Security": "max-age=31536000", "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=()", "Server": "nginx",
}


def test_good_headers_produce_no_findings():
    assert analyze_security_headers(GOOD, is_https=True) == []


def test_missing_headers_flagged():
    titles = " ".join(f.title for f in analyze_security_headers({}, is_https=True))
    for name in ("Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
                 "X-Content-Type-Options", "Referrer-Policy"):
        assert name in titles


def test_hsts_not_required_on_http_and_frame_ancestors_counts():
    headers = {**GOOD}
    del headers["Strict-Transport-Security"], headers["X-Frame-Options"]
    headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    assert analyze_security_headers(headers, is_https=False) == []


def test_short_hsts_and_version_disclosure():
    headers = {**GOOD, "Strict-Transport-Security": "max-age=300", "Server": "Apache/2.4.1",
               "X-Powered-By": "PHP/8.1"}
    findings = analyze_security_headers(headers, is_https=True)
    assert any("max-age" in f.title for f in findings)
    assert sum(f.category == "information-disclosure" for f in findings) == 2


def test_cookie_parsing_and_flags():
    assert parse_set_cookie("sid=1; Path=/; HttpOnly; SameSite=Lax") == ("sid", {"path", "httponly", "samesite"}, "lax")
    assert analyze_cookies(["sessionid=1; Secure; HttpOnly; SameSite=Lax"], True) == []
    weak = analyze_cookies(["sessionid=1; Path=/"], True)[0]
    assert weak.severity == Severity.MEDIUM and "Secure" in weak.title and "HttpOnly" in weak.title
    assert analyze_cookies(["theme=dark; Path=/"], False)[0].severity == Severity.LOW
    csrf = analyze_cookies(["csrftoken=1; Secure; SameSite=Lax"], True)
    assert csrf == []  # readable CSRF cookie is by design
    assert "SameSite=None" in analyze_cookies(["a=1; HttpOnly; SameSite=None"], False)[0].title


def test_cdn_detection():
    assert detect_cdn({"CF-RAY": "abc", "Server": "cloudflare"}) == ["Cloudflare"]
    assert detect_cdn({"Via": "1.1 x.cloudfront.net (CloudFront)", "X-Cache": "Hit"}) == ["Amazon CloudFront"]
    assert detect_cdn({"Server": "nginx"}) == []
    assert detect_cdn({"X-Cache": "HIT"}) == ["CDN/Cache (غير محدد)"]


def test_extract_hidden_field():
    html = '<input value="abc" name="csrfmiddlewaretoken" type="hidden"><input type="hidden" name="next" value="/">'
    assert extract_hidden_field(html, "csrfmiddlewaretoken") == "abc"
    assert extract_hidden_field(html, "missing") is None


def test_stress_steps_respect_duration_and_max():
    config = TestConfig(TestType.STRESS, "s", duration_s=30,
                        extra={"start_users": 5, "step_users": 10, "max_users": 22, "step_duration_s": 10})
    assert [(s.users, s.duration_s) for s in build_steps(config)] == [(5, 10), (15, 10), (22, 10)]
    config.duration_s = 20
    assert [s.users for s in build_steps(config)] == [5, 15]


def test_sustainable_users_is_never_estimated():
    th = Thresholds()
    assert max_sustainable_tested_users(TestType.LOAD, {"total": 0}, {}, th) is None
    assert max_sustainable_tested_users(TestType.LOAD, {"total": 10, "error_rate": 0.9, "peak_users": 5}, {}, th) is None
    assert max_sustainable_tested_users(TestType.LOAD, {"total": 10, "error_rate": 0, "p95_ms": 50, "peak_users": 5}, {}, th) == 5
    assert max_sustainable_tested_users(TestType.STRESS, {"total": 10}, {"max_sustainable_users": None}, th) is None
    assert max_sustainable_tested_users(TestType.SECURITY, {"total": 10, "peak_users": 1}, {}, th) is None


def test_performance_findings_come_from_measurements():
    clean = analyze_performance(TestType.LOAD, {"total": 100, "error_rate": 0.0, "p50_ms": 20, "p95_ms": 40, "p99_ms": 60}, [])
    assert [f.severity for f in clean] == [Severity.INFO]
    bad = analyze_performance(
        TestType.LOAD,
        {"total": 100, "failed": 30, "error_rate": 0.3, "s5xx": 20, "transport_errors": 10,
         "error_kinds": {"timeout": 10}, "p50_ms": 50, "p95_ms": 3000, "p99_ms": 9000}, [])
    titles = " ".join(f.title for f in bad)
    assert "5xx" in titles and "مهلات" in titles and "tail latency" in titles and "مرتفع" in titles
    assert analyze_performance(TestType.SECURITY, {"total": 5}, []) == []
    series = [{"users": u, "requests": 5, "avg_ms": ms} for u, ms in
              [(2, 20), (2, 22), (2, 21), (10, 200), (10, 210), (10, 190)]]
    grow = analyze_performance(TestType.STRESS, {"total": 30, "error_rate": 0, "p50_ms": 20, "p95_ms": 60, "p99_ms": 70}, series)
    assert any("يتضاعف" in f.title for f in grow)


def test_executive_summary_states_limits_honestly():
    lines = executive_summary({"test_type": "load", "summary": {
        "total": 10, "success": 10, "failed": 0, "error_rate": 0.0, "elapsed_s": 2, "rps": 5,
        "avg_ms": 1, "p50_ms": 1, "p95_ms": 2, "p99_ms": 3, "max_sustainable_tested_users": 5}, "findings": []})
    assert any("ليست السعة القصوى" in line for line in lines)
    none = executive_summary({"test_type": "stress", "summary": {"total": 0}, "findings": []})
    assert any("لم تُسجَّل" in line for line in none) and any("لم يثبت" in line for line in none)
