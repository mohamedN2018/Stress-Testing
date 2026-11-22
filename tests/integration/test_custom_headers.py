"""Custom request headers: sent to the target, validated, and never persisted."""

from __future__ import annotations

import pytest

from sentinel_test_lab.core.models import Backend, TestConfig, TestType
from sentinel_test_lab.core.safety_manager import SafetyViolation, parse_headers
from sentinel_test_lab.reporting.export import to_json
from sentinel_test_lab.reporting.html_report import render_html

SECRET = "tok-9f8e7d6c5b4a-secret"


def load(headers: dict | None, **kw) -> TestConfig:
    extra = {"_headers": headers, "header_names": ", ".join(headers)} if headers else {}
    base = dict(test_type=TestType.LOAD, name="hdr", users=1, duration_s=2, rate_limit_rps=5,
                interval_s=0.0, paths=["/ok"], timeout_s=5, extra=extra)
    base.update(kw)
    return TestConfig(**base)


def test_parse_headers():
    assert parse_headers("Cookie: sessionid=abc | Authorization: Bearer x:y") == {
        "Cookie": "sessionid=abc", "Authorization": "Bearer x:y"}
    assert parse_headers("  ") == {}
    assert parse_headers("no-colon-here") == {"no-colon-here": ""}


@pytest.mark.integration
async def test_headers_reach_the_server_but_are_never_stored(env, server, tmp_path):
    target = env.add_target(server.url)
    record = await env.run(load({"Authorization": f"Bearer {SECRET}", "X-Test-Run": "1"}), target)
    assert record.summary["total"] >= 1
    assert server.last_headers["Authorization"] == f"Bearer {SECRET}"
    assert server.last_headers["X-Test-Run"] == "1"
    assert server.last_headers["User-Agent"].startswith("SentinelTestLab")   # cannot be overridden

    assert "_headers" not in record.config["extra"]
    assert record.config["extra"]["header_names"] == "Authorization, X-Test-Run"
    assert SECRET not in render_html(record) and SECRET not in to_json(record)
    assert "Authorization, X-Test-Run" in render_html(record)
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert SECRET.encode() not in path.read_bytes(), path


@pytest.mark.parametrize("headers", [
    {"Host": "other-site.example"},
    {"X-Forwarded-For": "1.2.3.4"},
    {"x-real-ip": "1.2.3.4"},
    {"User-Agent": "Mozilla/5.0"},
    {"Bad Name": "x"},
    {"no-colon-here": ""},
    {"X-Test": "a\r\nInjected: 1"},
    {f"X-H{i}": "v" for i in range(11)},
])
def test_dangerous_or_malformed_headers_are_rejected(env, headers):
    target = env.add_target("http://127.0.0.1:8000")
    with pytest.raises(SafetyViolation):
        env.safety.authorize_run(load(headers), target, confirmed=True, elevated_confirmation="")


def test_headers_only_with_the_internal_engine(env):
    target = env.add_target("http://127.0.0.1:8000")
    with pytest.raises(SafetyViolation):
        env.safety.authorize_run(load({"X-Test": "1"}, backend=Backend.K6), target,
                                 confirmed=True, elevated_confirmation="")
    assert env.safety.authorize_run(load({"X-Test": "1"}), target, confirmed=True, elevated_confirmation="")
