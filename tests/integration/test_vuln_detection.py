"""Vulnerability detection against deliberately vulnerable pages of the local server."""

from __future__ import annotations

import pytest

from sentinel_test_lab.core.models import Environment, Severity, TestConfig, TestType
from sentinel_test_lab.core.safety_manager import SafetyViolation
from sentinel_test_lab.reporting.html_report import render_html

pytestmark = pytest.mark.integration


def sec(paths, **extra) -> TestConfig:
    return TestConfig(test_type=TestType.SECURITY, name="vuln", users=1, duration_s=60,
                      rate_limit_rps=5, interval_s=0.0, paths=paths, timeout_s=5, extra=extra)


def cwes(record) -> set[str]:
    return {f.cwe for f in record.findings}


async def test_html_analysis_finds_page_level_issues(env, server):
    target = env.add_target(server.url)
    record = await env.run(sec(["/vuln"]), target)
    assert {"CWE-352", "CWE-319", "CWE-353", "CWE-1104", "CWE-798", "CWE-615"} <= cwes(record)
    secret = next(f for f in record.findings if f.cwe == "CWE-798")
    assert "AKIAIOSFODNN7EXAMPLE" not in secret.evidence          # masked
    assert all(f.owasp.startswith("A0") for f in record.findings if f.cwe)
    assert record.details["input_probes"] == {"status": "لم يُطلب"}


async def test_exposed_files_and_admin_panel(env, server):
    target = env.add_target(server.url)
    clean = await env.run(sec(["/ok"]), target)
    assert clean.details["exposure_checks"]["/.git/config"] is False
    assert clean.details["exposure_checks"]["/admin/"] is False
    server.expose_files = True
    record = await env.run(sec(["/ok"]), target)
    checks = record.details["exposure_checks"]
    assert checks["/.git/config"] is True and checks["/admin/"] is True and checks["/db.sqlite3"] is False
    git = next(f for f in record.findings if f.evidence == "/.git/config")
    assert git.severity == Severity.HIGH and git.cwe == "CWE-538"
    assert any("Django" in f.title and f.evidence == "/admin/" for f in record.findings)


async def test_exposure_checks_respect_path_scope(env, server):
    server.expose_files = True
    target = env.add_target(server.url, allowed_paths=["/secure"])
    record = await env.run(sec(["/secure"]), target)
    assert {p for _, _, p in server.hits} == {"/secure"}
    assert set(record.details["exposure_checks"].values()) == {None}
    coverage = {c["check"]: c["result"] for c in record.details["coverage"]}
    assert "خارج النطاق" in coverage["ملفات ولوحات مكشوفة"]


async def test_input_probes_detect_reflection_sql_error_and_open_redirect(env, server):
    target = env.add_target(server.url)
    paths = ["/vuln/search?q=test", "/vuln/item?id=1", "/vuln/go?next=/home", "/vuln/safe-search?q=test"]
    record = await env.run(sec(paths, input_probes=True), target)
    found = {f.cwe: f for f in record.findings if f.category == "injection"}
    assert set(found) == {"CWE-79", "CWE-89", "CWE-601"}
    assert "/vuln/search" in found["CWE-79"].evidence and "q" in found["CWE-79"].evidence
    assert "/vuln/item" in found["CWE-89"].evidence
    assert "/vuln/go" in found["CWE-601"].evidence
    assert not any("safe-search" in f.evidence for f in record.findings)   # escaped output is not flagged
    assert record.details["input_probes"]["parameters_probed"] == 4
    # redirects are never followed and only GET is used
    assert all(method == "GET" for _, method, _ in server.hits)
    assert record.summary["total"] == len(server.hits)


async def test_input_probes_are_not_sent_unless_requested(env, server):
    target = env.add_target(server.url)
    await env.run(sec(["/vuln/search?q=test"]), target)
    assert len(server.hits_for("/vuln/search")) == 1     # the page itself, no probe requests


async def test_input_probes_rejected_on_unverified_public_target(env, server):
    public = env.add_target("https://example.com", name="pub", ips=["93.184.216.34"],
                            environment=Environment.PRODUCTION, allow_private=False)
    with pytest.raises(SafetyViolation):
        await env.run(sec(["/search?q=1"], input_probes=True), public)
    assert server.hits == []


async def test_posture_score_and_coverage_reach_the_report(env, server):
    target = env.add_target(server.url)
    record = await env.run(sec(["/vuln", "/vuln/item?id=1"], input_probes=True), target)
    posture = record.details["posture"]
    assert posture["grade"] in ("D", "F") and posture["counts"]["high"] >= 2
    assert any(key.startswith("A03:2021") for key in posture["by_owasp"])
    html = render_html(record)
    for text in ("مؤشر الوضع الأمني", "ما تم فحصه في هذا التشغيل", "CWE-89", "A03:2021 Injection"):
        assert text in html, text
