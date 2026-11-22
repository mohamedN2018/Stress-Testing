from __future__ import annotations

import threading

import pytest

from sentinel_test_lab.core.config import Settings
from sentinel_test_lab.core.metrics_collector import MetricsCollector
from sentinel_test_lab.core.models import Finding, RunRecord, RunStatus, Severity, TestConfig, TestType
from sentinel_test_lab.core.rate_limiter import RateLimiter
from sentinel_test_lab.database.db import Database
from sentinel_test_lab.database.repository import Repository
from sentinel_test_lab.monitoring.performance_metrics import LatencyHistogram
from sentinel_test_lab.monitoring.system_metrics import SystemMetricsSampler


# ---------------------------------------------------------------- histogram
def test_histogram_percentiles_within_two_percent():
    hist = LatencyHistogram()
    for value in range(1, 1001):
        hist.record(float(value))
    for pct, expected in ((50, 500), (90, 900), (95, 950), (99, 990)):
        assert hist.percentile(pct) == pytest.approx(expected, rel=0.025)
    assert hist.mean_ms == pytest.approx(500.5)
    assert hist.min_ms == 1 and hist.max_ms == 1000


def test_empty_histogram_reports_none():
    hist = LatencyHistogram()
    assert hist.percentile(95) is None and hist.mean_ms is None
    assert hist.summary()["p99_ms"] is None


def test_single_sample_percentile_is_exact():
    hist = LatencyHistogram()
    hist.record(42.0)
    assert hist.percentile(50) == 42.0 and hist.percentile(99) == 42.0


# ---------------------------------------------------------------- collector
def test_collector_classifies_status_codes():
    metrics = MetricsCollector()
    for status in (200, 201, 301, 404, 429, 500, 503, None):
        metrics.record(status, 10.0, "timeout" if status is None else None)
    snap = metrics.snapshot()
    assert (snap.total, snap.success, snap.failed) == (8, 3, 5)
    assert (snap.s2xx, snap.s3xx, snap.s4xx, snap.s5xx, snap.s429) == (2, 1, 2, 2, 1)
    assert snap.transport_errors == 1 and snap.error_kinds == {"timeout": 1}
    assert snap.error_rate == pytest.approx(0.625)


def test_collector_without_samples_has_no_values():
    snap = MetricsCollector().snapshot()
    assert snap.total == 0
    assert snap.rps is None and snap.avg_ms is None and snap.p95_ms is None and snap.error_rate is None


def test_collector_phases_and_series():
    metrics = MetricsCollector()
    metrics.set_users(3)
    metrics.set_phase("a")
    metrics.record(200, 10)
    metrics.record(500, 30)
    metrics.set_phase("b")
    metrics.set_users(7)
    metrics.record(200, 5)
    sample = metrics.tick({"cpu_percent": 1.0})
    assert sample["requests"] == 3 and sample["failed"] == 1 and sample["system"]["cpu_percent"] == 1.0
    # an immediate second tick is a short trailing interval: folded, nothing counted twice
    assert metrics.tick()["requests"] == 3 and len(metrics.series) == 1
    metrics.record(200, 7)
    assert metrics.tick()["requests"] == 4 and len(metrics.series) == 1
    phases = metrics.all_phases()
    assert phases["a"]["total"] == 2 and phases["a"]["error_rate"] == 0.5 and phases["a"]["users"] == 3
    assert phases["b"]["total"] == 2 and phases["b"]["users"] == 7  # two requests were recorded in phase b
    metrics.finish()
    summary = metrics.summary()
    assert summary["total"] == 4 and summary["peak_users"] == 7


def test_collector_is_thread_safe():
    metrics = MetricsCollector()

    def work():
        for _ in range(5000):
            metrics.record(200, 1.0)

    threads = [threading.Thread(target=work) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert metrics.snapshot().total == 40_000


def test_rate_limiter_rejects_unlimited():
    for rate in (0, -1):
        with pytest.raises(ValueError):
            RateLimiter(rate)


def test_system_metrics_are_real_values():
    sampler = SystemMetricsSampler()
    first = sampler.sample()
    __import__('time').sleep(0.1)
    second = sampler.sample()
    assert 0 <= first.ram_percent <= 100
    assert first.net_sent_kbps is None  # needs two samples: never invented
    assert second.net_sent_kbps is not None and second.net_sent_kbps >= 0


# ------------------------------------------------------------------ storage
def make_run(name="run", test_type=TestType.LOAD, status=RunStatus.COMPLETED, url="http://a.test") -> RunRecord:
    return RunRecord(name=name, test_type=test_type, target_id=None, target_url=url, status=status,
                     started_at="2026-01-01T00:00:00+00:00", config=TestConfig(test_type, name).to_dict(),
                     summary={"total": 5}, series=[{"t": 1}],
                     findings=[Finding(Severity.HIGH, "c", "عنوان", "تفصيل")])


def test_migrations_are_idempotent(tmp_path):
    path = tmp_path / "x.db"
    assert Database(path).migrate() == 1
    assert Database(path).migrate() == 1


def test_run_roundtrip_search_filter_delete(tmp_path):
    repo = Repository(Database(tmp_path / "x.db"))
    first = repo.save_run(make_run("checkout load"))
    repo.save_run(make_run("login stress", TestType.STRESS, RunStatus.AUTO_STOPPED, "http://b.test"))
    loaded = repo.get_run(first.id)
    assert loaded.findings[0].title == "عنوان" and loaded.summary == {"total": 5}
    assert [r.name for r in repo.list_runs(search="checkout")] == ["checkout load"]
    assert [r.name for r in repo.list_runs(search="b.test")] == ["login stress"]
    assert len(repo.list_runs(test_type="stress")) == 1
    assert len(repo.list_runs(status="completed")) == 1
    repo.delete_run(first.id)
    assert repo.get_run(first.id) is None and repo.counts()["runs"] == 1


def test_update_run_keeps_id(tmp_path):
    repo = Repository(Database(tmp_path / "x.db"))
    run = repo.save_run(make_run(status=RunStatus.RUNNING))
    run.status = RunStatus.COMPLETED
    repo.save_run(run)
    assert repo.counts()["runs"] == 1 and repo.get_run(run.id).status == RunStatus.COMPLETED


def test_interrupted_runs_closed_on_startup(tmp_path):
    repo = Repository(Database(tmp_path / "x.db"))
    run = repo.save_run(make_run(status=RunStatus.RUNNING))
    assert repo.mark_interrupted_runs() == 1
    assert repo.get_run(run.id).status == RunStatus.FAILED


def test_target_roundtrip_and_reauthorization_keeps_ownership(env):
    target = env.add_target("http://127.0.0.1:8000", allowed_paths=["/a", "/b"])
    target.ownership_verified = True
    env.repo.save_target(target)
    again = env.add_target("http://127.0.0.1:8000", name="renamed")
    assert again.id == target.id and again.ownership_verified and again.verify_token == target.verify_token
    stored = env.repo.get_target(target.id)
    assert stored.name == "renamed" and stored.network_class == "loopback"
    assert len(env.repo.list_targets()) == 1
    env.repo.delete_target(target.id)
    assert env.repo.get_target(target.id) is None


def test_settings_persist(tmp_path):
    repo = Repository(Database(tmp_path / "x.db"))
    assert repo.load_settings() == Settings()
    settings = Settings(elevated_enabled=True, zap_url="http://127.0.0.1:8090")
    settings.thresholds.max_p95_ms = 1234
    repo.save_settings(settings)
    assert repo.load_settings() == settings


def test_config_never_persists_private_extras():
    config = TestConfig(TestType.BRUTE_FORCE, "x", extra={"attempts": 3, "_secret": "s3cr3t"})
    assert "_secret" not in config.to_dict()["extra"]
    assert TestConfig.from_dict(config.to_dict()).extra == {"attempts": 3}
