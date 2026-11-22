from __future__ import annotations

import asyncio
import time

import pytest

from sentinel_test_lab.core.config import (
    ABSOLUTE_LIMITS,
    BRUTE_FORCE_MAX_ATTEMPTS,
    DEFAULT_LIMITS,
    FLOOD_MAX_DURATION_S,
    Settings,
    Thresholds,
)
from sentinel_test_lab.core.metrics_collector import MetricsCollector
from sentinel_test_lab.core.models import Backend, Environment, TestConfig, TestType
from sentinel_test_lab.core.safety_manager import (
    STOP_LIMIT,
    STOP_SAFETY,
    STOP_USER,
    RunGuard,
    SafetyViolation,
)

PUBLIC = dict(ips=["93.184.216.34"], environment=Environment.PRODUCTION, allow_private=False)


def load(**kw) -> TestConfig:
    base = dict(test_type=TestType.LOAD, name="t", users=5, duration_s=30, rate_limit_rps=5)
    base.update(kw)
    return TestConfig(**base)


def authorize(env, config, target, confirmed=True, elevated=""):
    return env.safety.authorize_run(config, target, confirmed=confirmed, elevated_confirmation=elevated)


# ------------------------------------------------------------- authorization
def test_default_limits_are_the_documented_safe_defaults():
    assert (DEFAULT_LIMITS.max_users, DEFAULT_LIMITS.max_duration_s, DEFAULT_LIMITS.max_rps) == (5, 60, 5.0)


def test_unknown_target_is_rejected(env):
    with pytest.raises(SafetyViolation):
        authorize(env, load(), None)


def test_unsaved_target_is_rejected(env):
    from sentinel_test_lab.core.authorization import build_target

    target = build_target(url="http://127.0.0.1:1", name="x", environment=Environment.LOCALHOST,
                          authorization_statement="owner of this box", confirmed=True,
                          resolved_ips=["127.0.0.1"], allow_private=True)
    with pytest.raises(SafetyViolation):
        authorize(env, load(), target)


def test_confirmation_is_required(env):
    target = env.add_target("http://127.0.0.1:8000")
    with pytest.raises(SafetyViolation):
        authorize(env, load(), target, confirmed=False)


def test_defaults_allowed_and_budget_derived(env):
    target = env.add_target("http://127.0.0.1:8000")
    approved = authorize(env, load(), target)
    assert approved.request_budget == 151  # 5 rps * 30 s (+1: the slot at t=0)


@pytest.mark.parametrize("override", [
    {"users": 6}, {"duration_s": 61}, {"rate_limit_rps": 5.5}, {"request_budget": 301},
])
def test_exceeding_defaults_rejected_without_elevated_settings(env, override):
    target = env.add_target("http://127.0.0.1:8000")
    with pytest.raises(SafetyViolation):
        authorize(env, load(**override), target, elevated=target.host)


def test_elevated_limits_need_typed_host_confirmation(env):
    target = env.add_target("http://127.0.0.1:8000")
    env.enable_elevated()
    config = load(users=25, rate_limit_rps=20)
    with pytest.raises(SafetyViolation):
        authorize(env, config, target)
    with pytest.raises(SafetyViolation):
        authorize(env, config, target, elevated="wrong-host")
    assert authorize(env, config, target, elevated="127.0.0.1").users == 25


def test_unverified_public_target_stays_on_default_limits(env):
    target = env.add_target("https://example.com", **PUBLIC)
    env.enable_elevated()
    assert env.safety.effective_limits(target) == DEFAULT_LIMITS
    with pytest.raises(SafetyViolation):
        authorize(env, load(users=10), target, elevated=target.host)
    assert authorize(env, load(), target).users == 5


def test_verified_public_target_gets_elevated_limits(env):
    target = env.add_target("https://example.com", **PUBLIC)
    target.ownership_verified = True
    env.repo.save_target(target)
    env.enable_elevated()
    assert authorize(env, load(users=10), target, elevated="example.com").users == 10


def test_maximum_elevated_run_is_authorized_for_a_trusted_target(env):
    target = env.add_target("http://127.0.0.1:8000")
    env.enable_elevated(
        elevated_max_users=ABSOLUTE_LIMITS.max_users,
        elevated_max_duration_s=ABSOLUTE_LIMITS.max_duration_s,
        elevated_max_rps=ABSOLUTE_LIMITS.max_rps,
        elevated_max_request_budget=ABSOLUTE_LIMITS.max_request_budget,
    )
    approved = authorize(
        env,
        load(users=ABSOLUTE_LIMITS.max_users, duration_s=ABSOLUTE_LIMITS.max_duration_s,
             rate_limit_rps=ABSOLUTE_LIMITS.max_rps),
        target, elevated=target.host,
    )
    assert approved.users == ABSOLUTE_LIMITS.max_users
    assert approved.rate_limit_rps == ABSOLUTE_LIMITS.max_rps
    assert 0 < approved.request_budget <= ABSOLUTE_LIMITS.max_request_budget


def test_absolute_ceiling_cannot_be_configured_away(env):
    target = env.add_target("http://127.0.0.1:8000")
    env.enable_elevated(elevated_max_users=10_000, elevated_max_rps=99_999,
                        elevated_max_duration_s=99_999, elevated_max_request_budget=10**9)
    limits = env.safety.effective_limits(target)
    assert limits == ABSOLUTE_LIMITS
    with pytest.raises(SafetyViolation):
        authorize(env, load(users=ABSOLUTE_LIMITS.max_users + 1), target, elevated=target.host)


@pytest.mark.parametrize("override", [
    {"rate_limit_rps": 0}, {"rate_limit_rps": float("inf")}, {"users": 0}, {"duration_s": 0},
    {"duration_s": float("nan")}, {"request_budget": -1}, {"timeout_s": 0},
])
def test_unbounded_or_invalid_values_rejected(env, override):
    target = env.add_target("http://127.0.0.1:8000")
    with pytest.raises(SafetyViolation):
        authorize(env, load(**override), target)


def test_stress_peak_users_counted_from_extras(env):
    target = env.add_target("http://127.0.0.1:8000")
    config = load(test_type=TestType.STRESS, users=1, extra={"max_users": 50})
    with pytest.raises(SafetyViolation):
        authorize(env, config, target, elevated=target.host)


def test_path_and_method_must_be_in_scope(env):
    target = env.add_target("http://127.0.0.1:8000", allowed_paths=["/api"], allowed_methods=["GET"])
    with pytest.raises(SafetyViolation):
        authorize(env, load(paths=["/admin"]), target)
    with pytest.raises(SafetyViolation):
        authorize(env, load(paths=["/api"], method="POST"), target)
    assert authorize(env, load(paths=["/api/x"]), target)


@pytest.mark.parametrize("test_type", [TestType.FLOOD, TestType.BRUTE_FORCE])
def test_sensitive_modules_need_a_trusted_target(env, test_type):
    target = env.add_target("https://example.com", **PUBLIC)
    extra = {"attempts": 3, "test_username": "qa", "test_account_confirmed": True}
    with pytest.raises(SafetyViolation):
        authorize(env, load(test_type=test_type, extra=extra), target)


def test_flood_caps(env):
    target = env.add_target("http://127.0.0.1:8000")
    env.enable_elevated(elevated_max_rps=200, elevated_max_duration_s=300)
    with pytest.raises(SafetyViolation):
        authorize(env, load(test_type=TestType.FLOOD, duration_s=FLOOD_MAX_DURATION_S + 1), target,
                  elevated=target.host)
    with pytest.raises(SafetyViolation):
        authorize(env, load(test_type=TestType.FLOOD, rate_limit_rps=51), target, elevated=target.host)


def test_brute_force_rules(env):
    target = env.add_target("http://127.0.0.1:8000")
    good = {"attempts": 5, "test_username": "qa-account", "test_account_confirmed": True}

    def config(**extra):
        return load(test_type=TestType.BRUTE_FORCE, users=1, rate_limit_rps=2, extra={**good, **extra})

    assert authorize(env, config(), target)
    for bad in ({"attempts": BRUTE_FORCE_MAX_ATTEMPTS + 1}, {"attempts": 0}, {"test_username": ""},
                {"test_account_confirmed": False}):
        with pytest.raises(SafetyViolation):
            authorize(env, config(**bad), target)
    fast = load(test_type=TestType.BRUTE_FORCE, users=1, interval_s=0.1, extra=good)
    with pytest.raises(SafetyViolation):
        authorize(env, fast, target)


def test_active_scan_needs_trust_and_separate_confirmation(env):
    local = env.add_target("http://127.0.0.1:8000")
    public = env.add_target("https://example.com", name="pub", **PUBLIC)
    sec = lambda **extra: load(test_type=TestType.SECURITY, users=1, extra=extra)  # noqa: E731
    with pytest.raises(SafetyViolation):
        authorize(env, sec(active_scan=True, active_scan_confirmed=True), public)
    with pytest.raises(SafetyViolation):
        authorize(env, sec(active_scan=True), local)
    assert authorize(env, sec(active_scan=True, active_scan_confirmed=True), local)
    assert authorize(env, sec(), public)  # passive assessment is fine on an unverified target
    # active rules probe the whole host and send POST: the scope must cover both
    api_only = env.add_target("http://127.0.0.1:8001", name="api", allowed_paths=["/api"])
    read_only = env.add_target("http://127.0.0.1:8002", name="ro", allowed_methods=["GET", "HEAD"])
    for narrow in (api_only, read_only):
        with pytest.raises(SafetyViolation):
            authorize(env, sec(active_scan=True, active_scan_confirmed=True), narrow)
        assert authorize(env, sec(use_zap=True), narrow)      # passive ZAP stays allowed


def test_external_backends_only_for_load(env):
    target = env.add_target("http://127.0.0.1:8000")
    with pytest.raises(SafetyViolation):
        authorize(env, load(test_type=TestType.STRESS, backend=Backend.K6), target)


def test_decisions_are_audited(env):
    target = env.add_target("http://127.0.0.1:8000")
    authorize(env, load(), target)
    with pytest.raises(SafetyViolation):
        authorize(env, load(users=500), target)
    events = [e["event"] for e in env.repo.list_audit()]
    assert "run_authorized" in events and "run_rejected" in events
    assert env.paths.audit_file.read_text(encoding="utf-8").count("\n") >= 2


def test_only_one_run_at_a_time(env):
    target = env.add_target("http://127.0.0.1:8000")
    env.orchestrator.prepare(load(), target.id, confirmed=True)
    with pytest.raises(SafetyViolation):
        env.orchestrator.prepare(load(), target.id, confirmed=True)


def test_settings_roundtrip_clamps():
    settings = Settings.from_dict({"elevated_max_users": ABSOLUTE_LIMITS.max_users + 5000,
                                   "unknown": 1, "thresholds": {"max_p95_ms": 1}})
    assert settings.elevated_limits().max_users == ABSOLUTE_LIMITS.max_users
    assert settings.thresholds.max_p95_ms == 1


# ------------------------------------------------------------------ RunGuard
def guard(budget=10, rps=1000.0, **th) -> tuple[RunGuard, MetricsCollector]:
    metrics = MetricsCollector()
    config = load(request_budget=budget, rate_limit_rps=rps, thresholds=Thresholds(**th))
    return RunGuard(config, metrics), metrics


def test_guard_requires_budget():
    with pytest.raises(SafetyViolation):
        RunGuard(load(request_budget=0), MetricsCollector())


async def test_guard_enforces_request_budget():
    g, _ = guard(budget=3)
    results = [await g.acquire() for _ in range(5)]
    assert results == [True, True, True, False, False]
    assert g.issued == 3 and g.exhausted and not g.stopped  # in-flight requests may finish
    g.budget_stop()
    assert g.stopped and g.stop_kind == STOP_LIMIT


async def test_guard_rate_limit_spacing():
    g, _ = guard(budget=100, rps=20)
    started = time.monotonic()
    for _ in range(11):
        assert await g.acquire()
    assert time.monotonic() - started >= 0.45  # 10 intervals of 50 ms


async def test_guard_emergency_stop_blocks_new_requests():
    g, _ = guard()
    g.emergency_stop()
    assert not await g.acquire()
    assert g.stop_kind == STOP_USER and g.issued == 0


def test_guard_first_stop_reason_wins():
    g, _ = guard()
    g.request_stop("first", STOP_SAFETY)
    g.emergency_stop()
    assert g.stop_reason == "first" and g.stop_kind == STOP_SAFETY


def test_guard_auto_stops_on_error_rate():
    g, metrics = guard(max_error_rate=0.2, min_samples=10, max_consecutive_failures=10_000)
    for i in range(20):
        metrics.record(500 if i % 2 else 200, 10)
    g.evaluate()
    assert g.stopped and g.stop_kind == STOP_SAFETY


def test_guard_ignores_small_samples():
    g, metrics = guard(max_error_rate=0.2, min_samples=10, max_consecutive_failures=10_000)
    for _ in range(5):
        metrics.record(500, 10)
    g.evaluate()
    assert not g.stopped


def test_guard_auto_stops_on_latency():
    g, metrics = guard(max_p95_ms=100, min_samples=10)
    for _ in range(20):
        metrics.record(200, 500)
    g.evaluate()
    assert g.stopped and "p95" in g.stop_reason


def test_guard_auto_stops_on_consecutive_failures():
    g, metrics = guard(max_consecutive_failures=5, min_samples=1000)
    for _ in range(5):
        metrics.record(None, 10, "connect_error")
    g.evaluate()
    assert g.stopped and g.stop_kind == STOP_SAFETY


def test_assessment_guard_tolerates_expected_4xx():
    metrics = MetricsCollector()
    config = load(test_type=TestType.BRUTE_FORCE, request_budget=50,
                  thresholds=Thresholds(max_error_rate=0.2, min_samples=5, max_consecutive_failures=5))
    g = RunGuard(config, metrics)
    for _ in range(20):
        metrics.record(401, 10)
    g.evaluate()
    assert not g.stopped
    for _ in range(20):
        metrics.record(503, 10)
    g.evaluate()
    assert g.stopped


def test_guard_deadline():
    now = [0.0]
    metrics = MetricsCollector()
    g = RunGuard(load(request_budget=10, duration_s=10, timeout_s=5), metrics, clock=lambda: now[0])
    g.evaluate()
    assert not g.stopped
    now[0] = 10 + 5 + RunGuard.DEADLINE_GRACE_S + 0.1
    g.evaluate()
    assert g.stopped and g.stop_kind == STOP_LIMIT


async def test_stop_is_thread_safe():
    g, _ = guard(budget=10_000, rps=10_000)
    loop = asyncio.get_running_loop()
    loop.call_later(0.05, lambda: __import__("threading").Thread(target=g.emergency_stop).start())
    while await g.acquire():
        await asyncio.sleep(0.001)
    assert g.stop_kind == STOP_USER


def test_input_probes_need_a_trusted_target(env):
    local = env.add_target("http://127.0.0.1:8000")
    public = env.add_target("https://example.com", name="pub", **PUBLIC)
    probes = load(test_type=TestType.SECURITY, users=1, extra={"input_probes": True})
    with pytest.raises(SafetyViolation):
        authorize(env, probes, public)
    assert authorize(env, probes, local)
