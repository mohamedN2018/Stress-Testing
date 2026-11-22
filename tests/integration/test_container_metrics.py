"""Server container metrics: parsing (always) and real `docker stats` (when Docker runs)."""

from __future__ import annotations

import time

import pytest

from sentinel_test_lab.core.models import TestConfig, TestType
from sentinel_test_lab.monitoring.container_metrics import (
    ContainerMetricsError,
    ContainerMetricsSampler,
    list_containers,
    parse_size,
    parse_stats_line,
    read_stats,
)
from sentinel_test_lab.reporting.html_report import render_html

LINE = ('{"BlockIO":"0B / 0B","CPUPerc":"12.50%","Container":"web","MemPerc":"3.10%",'
        '"MemUsage":"248.5MiB / 7.77GiB","Name":"web","NetIO":"1.2kB / 3MB","PIDs":"14"}')


def test_parse_size_units():
    assert parse_size("0B") == 0
    assert parse_size("1.5kB") == 1500
    assert parse_size(" 2MiB ") == 2 * 1024 ** 2
    assert parse_size("1GiB") == 1024 ** 3
    assert parse_size("--") is None and parse_size("12 parsecs") is None


def test_parse_stats_line():
    sample = parse_stats_line(LINE)
    assert sample == {
        "cpu_percent": 12.5, "mem_percent": 3.1, "mem_used_mb": 248.5,
        "mem_limit_mb": round(7.77 * 1024, 1), "net_rx_bytes": 1200.0, "net_tx_bytes": 3e6, "pids": 14,
    }
    assert parse_stats_line("not json") is None
    assert parse_stats_line('{"CPUPerc":"--","MemUsage":"-- / --"}') is None
    assert parse_stats_line("[1, 2]") is None


@pytest.mark.parametrize("name", ["", "web; rm -rf /", "$(reboot)", "a b", "-flag", "web|cat"])
def test_unsafe_container_names_are_rejected_before_any_command(name):
    with pytest.raises(ContainerMetricsError):
        read_stats(name)


def test_unsafe_ssh_host_is_rejected():
    with pytest.raises(ContainerMetricsError):
        list_containers("host; reboot")
    with pytest.raises(ContainerMetricsError):
        read_stats("web", "-oProxyCommand=calc")


# ------------------------------------------------------------- real Docker
def _running_container() -> str:
    try:
        names = list_containers(timeout=8)
    except ContainerMetricsError as exc:
        pytest.skip(f"Docker غير متاح: {exc}")
    if not names:
        pytest.skip("لا توجد حاويات تعمل")
    return names[0]


@pytest.mark.docker
def test_real_docker_stats():
    sample = read_stats(_running_container())
    assert sample["cpu_percent"] is not None and sample["cpu_percent"] >= 0
    assert sample["mem_used_mb"] is not None and sample["mem_used_mb"] > 0


@pytest.mark.docker
def test_missing_container_reports_an_error_and_stops_polling():
    _running_container()
    sampler = ContainerMetricsSampler("sentinel-no-such-container", interval_s=0.05).start()
    deadline = time.monotonic() + 30
    while sampler._thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.1)
    assert not sampler._thread.is_alive()          # gave up after repeated failures
    assert sampler.error and sampler.latest() is None and sampler.samples == 0


@pytest.mark.docker
@pytest.mark.integration
async def test_run_records_container_metrics_and_reports_them(env, server):
    container = _running_container()
    settings = env.repo.load_settings()
    settings.monitor_container = container
    env.repo.save_settings(settings)
    target = env.add_target(server.url)
    config = TestConfig(test_type=TestType.LOAD, name="docker", users=2, duration_s=8, rate_limit_rps=5,
                        interval_s=0.0, paths=["/ok"], timeout_s=5)
    record = await env.run(config, target)
    monitor = record.summary["container_monitor"]
    assert monitor["container"] == container and monitor["samples"] >= 1 and monitor["error"] == ""
    samples = [s["container"] for s in record.series if s.get("container")]
    assert samples and all(s["mem_used_mb"] > 0 for s in samples)
    assert f"موارد حاوية الخادم (Docker): {container}" in render_html(record)


@pytest.mark.integration
async def test_run_without_container_setting_has_no_container_data(env, server):
    target = env.add_target(server.url)
    config = TestConfig(test_type=TestType.LOAD, name="plain", users=1, duration_s=2, rate_limit_rps=5,
                        interval_s=0.0, paths=["/ok"], timeout_s=5)
    record = await env.run(config, target)
    assert "container_monitor" not in record.summary
    assert not any("container" in s for s in record.series)
    assert "موارد حاوية الخادم" not in render_html(record)
