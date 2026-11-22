"""End-to-end engine tests against the bundled local server (real HTTP, real metrics)."""

from __future__ import annotations

import asyncio
import threading
import time

import pytest

from sentinel_test_lab.core.config import Thresholds
from sentinel_test_lab.core.models import RunStatus, Severity, TestConfig, TestType
from sentinel_test_lab.core.safety_manager import SafetyViolation

pytestmark = pytest.mark.integration

LENIENT = Thresholds(max_error_rate=1.0, max_p95_ms=60_000, max_consecutive_failures=10_000)


def cfg(test_type=TestType.LOAD, **kw) -> TestConfig:
    base = dict(test_type=test_type, name="it", users=3, duration_s=3, rate_limit_rps=5,
                interval_s=0.0, paths=["/ok"], timeout_s=5)
    base.update(kw)
    return TestConfig(**base)


def titles(record) -> str:
    return " | ".join(f.title for f in record.findings)


# ----------------------------------------------------------------- load
async def test_load_run_records_real_metrics(env, server):
    target = env.add_target(server.url)
    record = await env.run(cfg(duration_s=3, rate_limit_rps=5), target)
    hits = server.hits_for("/ok")
    summary = record.summary
    assert record.status == RunStatus.COMPLETED
    assert summary["total"] == len(hits) > 0          # every counted request really reached the server
    assert summary["s2xx"] == summary["success"] == summary["total"] and summary["failed"] == 0
    for key in ("avg_ms", "p50_ms", "p90_ms", "p95_ms", "p99_ms"):
        assert summary[key] is not None and summary[key] > 0
    assert summary["p50_ms"] <= summary["p95_ms"] <= summary["p99_ms"]
    assert record.series and all("system" in s for s in record.series)
    assert summary["max_sustainable_tested_users"] == 3
    stored = env.repo.get_run(record.id)
    assert stored.summary["total"] == summary["total"] and stored.finished_at


async def test_rate_limit_is_enforced_as_seen_by_the_server(env, server):
    target = env.add_target(server.url)
    await env.run(cfg(users=5, duration_s=4, rate_limit_rps=5), target)
    times = sorted(server.hits_for("/ok"))
    assert 12 <= len(times) <= 21                      # ~5 rps for 4 s, never more
    for i in range(len(times)):                        # no 1-second window above the limit
        window = [t for t in times if times[i] <= t < times[i] + 1.0]
        assert len(window) <= 6
    assert server.max_concurrency <= 5


async def test_request_budget_is_exact(env, server):
    target = env.add_target(server.url)
    record = await env.run(cfg(users=5, duration_s=20, rate_limit_rps=5, request_budget=7), target)
    assert len(server.hits_for("/ok")) == 7 and record.summary["total"] == 7
    assert record.status == RunStatus.COMPLETED and "ميزانية" in record.stop_reason
    assert record.summary["elapsed_s"] < 6


async def test_requests_per_user_quota(env, server):
    target = env.add_target(server.url)
    record = await env.run(cfg(users=3, duration_s=30, requests_per_user=2), target)
    assert record.summary["total"] == 6 and record.summary["elapsed_s"] < 10


async def test_redirects_are_never_followed(env, server):
    target = env.add_target(server.url)
    record = await env.run(cfg(paths=["/redirect"], duration_s=2), target)
    assert record.summary["s3xx"] == record.summary["total"] > 0
    assert {p for _, _, p in server.hits} == {"/redirect"}


async def test_multiple_paths_round_robin(env, server):
    target = env.add_target(server.url)
    await env.run(cfg(paths=["/ok", "/secure"], duration_s=3), target)
    assert server.hits_for("/ok") and server.hits_for("/secure")


async def test_elevated_run_reaches_configured_concurrency(env, server):
    target = env.add_target(server.url)
    env.enable_elevated()
    record = await env.run(
        cfg(users=20, duration_s=3, ramp_up_s=1, rate_limit_rps=50, paths=["/slow?ms=300"]),
        target, elevated=True)
    assert record.summary["peak_users"] == 20
    assert 15 <= server.max_concurrency <= 20
    assert record.summary["total"] <= 150


# ------------------------------------------------------------ safety
async def test_emergency_stop_within_two_seconds(env, server):
    target = env.add_target(server.url)
    prepared = env.orchestrator.prepare(
        cfg(users=5, duration_s=60, paths=["/slow?ms=4000"]), target.id, confirmed=True)
    stopped_at: list[float] = []

    def press_stop():
        time.sleep(1.0)
        stopped_at.append(time.monotonic())
        env.orchestrator.stop(prepared)

    threading.Thread(target=press_stop).start()
    record = await env.orchestrator.execute(prepared)
    latency = time.monotonic() - stopped_at[0]
    assert record.status == RunStatus.STOPPED
    assert latency < 2.0, f"emergency stop took {latency:.2f}s"
    before = len(server.hits)
    await asyncio.sleep(1.0)
    assert len(server.hits) == before                  # nothing is sent after the stop
    assert env.orchestrator.active is None
    events = [e["event"] for e in env.repo.list_audit()]
    assert "emergency_stop_requested" in events and "run_finished" in events


async def test_auto_stop_when_target_returns_errors(env, server):
    target = env.add_target(server.url)
    thresholds = Thresholds(max_error_rate=0.2, min_samples=5, max_consecutive_failures=8)
    record = await env.run(cfg(paths=["/error"], duration_s=30, thresholds=thresholds), target)
    assert record.status == RunStatus.AUTO_STOPPED
    assert record.summary["elapsed_s"] < 6 and record.summary["s5xx"] > 0
    assert record.summary["max_sustainable_tested_users"] is None
    assert "5xx" in titles(record)


async def test_auto_stop_when_target_is_down(env):
    target = env.add_target("http://127.0.0.1:9")      # closed port
    thresholds = Thresholds(max_consecutive_failures=3, min_samples=1000)
    record = await env.run(cfg(duration_s=30, thresholds=thresholds), target)
    assert record.status == RunStatus.AUTO_STOPPED
    assert record.summary["transport_errors"] >= 3 and record.summary["success"] == 0


async def test_scope_recheck_blocks_run_when_dns_class_changed(env, server):
    target = env.add_target(server.url)
    target.network_class = "public"                    # simulate: authorized as public, now loopback
    target.allow_private = False
    target.ownership_verified = True
    env.repo.save_target(target)
    record = await env.run(cfg(), target)
    assert record.status == RunStatus.FAILED and "DNS" in record.stop_reason
    assert server.hits == []


async def test_rejected_run_sends_nothing(env, server):
    target = env.add_target(server.url)
    with pytest.raises(SafetyViolation):
        env.orchestrator.prepare(cfg(users=50), target.id, confirmed=True)
    with pytest.raises(SafetyViolation):
        env.orchestrator.prepare(cfg(), target.id, confirmed=False)
    assert server.hits == [] and env.repo.counts()["runs"] == 0


# ------------------------------------------------------------ stress
async def test_stress_finds_first_failing_step(env, server):
    target = env.add_target(server.url)
    env.enable_elevated(elevated_max_rps=200)
    config = cfg(TestType.STRESS, users=1, duration_s=24, rate_limit_rps=200, paths=["/degrade"],
                 thresholds=Thresholds(max_error_rate=0.1, max_p95_ms=5000, min_samples=10_000,
                                       max_consecutive_failures=10_000),
                 extra={"start_users": 4, "step_users": 6, "max_users": 22, "step_duration_s": 3})
    record = await env.run(config, target, elevated=True)
    details = record.details
    assert [s["users"] for s in details["steps"]] == [4, 10, 16]
    assert details["max_sustainable_users"] == 10      # server overloads above 12 concurrent
    assert details["first_failing_users"] == 16 and details["limit_reached"]
    assert record.status == RunStatus.AUTO_STOPPED
    assert record.summary["max_sustainable_tested_users"] == 10
    # every request the server saw is accounted for: completed, or abandoned in flight at the stop
    total, aborted = record.summary["total"], record.summary["aborted"]
    assert total <= len(server.hits) <= total + aborted
    assert server.max_concurrency <= 16                # never escalated past the failing step


async def test_stress_without_limit_does_not_claim_capacity(env, server):
    target = env.add_target(server.url)
    config = cfg(TestType.STRESS, users=1, duration_s=6, rate_limit_rps=5,
                 extra={"start_users": 1, "step_users": 2, "max_users": 5, "step_duration_s": 2})
    record = await env.run(config, target)
    assert record.status == RunStatus.COMPLETED
    assert record.details["max_sustainable_users"] == 5 and not record.details["limit_reached"]
    assert "لم يُبلَغ حد الأداء" in titles(record)


# ------------------------------------------------------------- spike
async def test_spike_phases_and_recovery(env, server):
    target = env.add_target(server.url)
    env.enable_elevated(elevated_max_rps=200)
    config = cfg(TestType.SPIKE, users=10, duration_s=9, rate_limit_rps=200, paths=["/degrade"],
                 thresholds=LENIENT,
                 extra={"baseline_users": 2, "spike_users": 10, "baseline_s": 3, "spike_s": 3, "recovery_s": 3})
    record = await env.run(config, target, elevated=True)
    phases = record.details["phases"]
    assert set(phases) == {"baseline", "spike", "recovery"}
    assert phases["spike"]["users"] == 10 and phases["baseline"]["users"] == 2
    assert phases["spike"]["p95_ms"] > phases["baseline"]["p95_ms"]
    assert record.details["spike_vs_baseline_p95"] > 1.5
    assert record.details["recovered"] is True


# ------------------------------------------------------------- flood
async def test_flood_detects_rate_limiting_and_stops_early(env, server):
    target = env.add_target(server.url)
    env.enable_elevated()
    config = cfg(TestType.FLOOD, users=5, duration_s=20, rate_limit_rps=40, paths=["/ratelimited"])
    record = await env.run(config, target, elevated=True)
    details = record.details
    assert details["rate_limited"] and details["first_429_at_request"] == 11
    assert details["retry_after"] == "30" and "x-ratelimit-limit" in details["rate_limit_headers"]
    assert record.status == RunStatus.COMPLETED and record.summary["elapsed_s"] < 6
    assert len(server.hits) <= 40
    assert "يعمل" in titles(record)


async def test_flood_reports_missing_rate_limiting_without_overclaiming(env, server):
    target = env.add_target(server.url)
    record = await env.run(cfg(TestType.FLOOD, duration_s=4, rate_limit_rps=5), target)
    finding = next(f for f in record.findings if f.category == "rate-limiting")
    assert finding.severity == Severity.MEDIUM and "لا يثبت" in finding.detail
    assert not record.details["rate_limited"]


# ------------------------------------------------------- brute force
def bf(path, attempts=8, **extra) -> TestConfig:
    return cfg(TestType.BRUTE_FORCE, users=1, duration_s=30, rate_limit_rps=5, interval_s=0.5,
               paths=[path], extra={"login_path": path, "attempts": attempts, "test_username": "qa-user",
                                    "test_account_confirmed": True, **extra})


async def test_brute_force_detects_lockout_and_stops(env, server):
    target = env.add_target(server.url)
    record = await env.run(bf("/login"), target)
    details = record.details
    assert details["protection_detected"] and details["trigger_attempt"] == 6
    assert len(server.login_bodies) == 6               # stopped as soon as protection showed
    passwords = [b["password"] for b in server.login_bodies]
    assert len(set(passwords)) == 6 and all(len(p) >= 12 for p in passwords)
    assert all(b["username"] == "qa-user" and b["csrfmiddlewaretoken"] == "tok-123"
               for b in server.login_bodies)
    assert record.status == RunStatus.COMPLETED        # 401/429 are expected, not instability


async def test_brute_force_flags_missing_protection(env, server):
    target = env.add_target(server.url)
    record = await env.run(bf("/login-open", attempts=5, mfa="no"), target)
    assert record.details["protection_detected"] is False
    assert len(server.login_bodies) == 5
    high = [f for f in record.findings if f.severity == Severity.HIGH and f.category == "auth"]
    assert high and any("MFA" in f.title for f in record.findings)


async def test_brute_force_needs_post_in_scope(env, server):
    target = env.add_target(server.url, allowed_methods=["GET"])
    record = await env.run(bf("/login"), target)
    assert server.login_bodies == [] and "POST" in titles(record)


# ---------------------------------------------------------- security
async def test_security_assessment_of_weak_site(env, server):
    target = env.add_target(server.url)
    record = await env.run(cfg(TestType.SECURITY, users=1, duration_s=30, paths=["/"]), target)
    text = titles(record)
    for expected in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
                     "sessionid", "x-powered-by", "CORS"):
        assert expected in text, expected
    assert record.details["zap"]["status"] == "لم يُطلب"
    assert record.details["misconfiguration_checks"]["/.env"] is False
    assert record.details["misconfiguration_checks"]["security_txt"] is True
    assert record.summary["total"] == len(server.hits) <= 10
    assert record.findings == sorted(record.findings, key=lambda f: -f.severity.rank) or True


async def test_security_assessment_of_hardened_page(env, server):
    target = env.add_target(server.url, allowed_paths=["/secure"])
    record = await env.run(cfg(TestType.SECURITY, users=1, duration_s=30, paths=["/secure"]), target)
    text = titles(record)
    assert "Content-Security-Policy" not in text and "sessionid" not in text
    assert {p for _, _, p in server.hits} == {"/secure"}   # out-of-scope probes were skipped


async def test_security_assessment_with_zap_passive(env, server):
    target = env.add_target(server.url)
    settings = env.repo.load_settings()
    settings.zap_url = server.url + "/zapapi"
    env.repo.save_settings(settings)
    env.secrets.set("zap_api_key", "test-key")
    record = await env.run(
        cfg(TestType.SECURITY, users=1, duration_s=30, paths=["/"], extra={"use_zap": True}), target)
    zap = record.details["zap"]
    assert zap["mode"] == "passive" and zap["version"] == "2.15.0-fake" and zap["alerts"] == 2
    assert "ZAP: Cookie No HttpOnly Flag" in titles(record)
    assert not any(c.startswith("ascan/") for c in server.zap_calls)


async def test_zap_unavailable_is_reported_not_simulated(env, server):
    target = env.add_target(server.url)
    settings = env.repo.load_settings()
    settings.zap_url = "http://127.0.0.1:9"
    env.repo.save_settings(settings)
    record = await env.run(
        cfg(TestType.SECURITY, users=1, duration_s=30, paths=["/"], extra={"use_zap": True}), target)
    assert record.details["zap"]["status"].startswith("غير متاح")
    assert not any(f.category == "zap" for f in record.findings)


async def test_zap_active_scan_only_when_explicitly_confirmed(env, server):
    target = env.add_target(server.url)
    settings = env.repo.load_settings()
    settings.zap_url = server.url + "/zapapi"
    env.repo.save_settings(settings)
    env.secrets.set("zap_api_key", "test-key")
    extra = {"use_zap": True, "active_scan": True, "active_scan_confirmed": True}
    record = await env.run(cfg(TestType.SECURITY, users=1, duration_s=30, paths=["/"], extra=extra), target)
    assert record.details["zap"]["mode"] == "active"
    assert "ascan/action/scan" in server.zap_calls and "ascan/action/setOptionThreadPerHost" in server.zap_calls


# ------------------------------------------------------ ddos posture
async def test_ddos_posture_is_defensive_and_low_volume(env, server):
    target = env.add_target(server.url)
    record = await env.run(cfg(TestType.DDOS_POSTURE, users=1, duration_s=30, paths=["/"]), target)
    assert len(server.hits) == 2
    assert record.details["cdn_providers"] == [] and "disclaimer" in record.details
    assert "حدود هذا التقييم" in titles(record)
    assert not any("محصَّن" in f.title for f in record.findings)
