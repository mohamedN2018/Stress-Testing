"""Target validation, ownership proof and the optional integrations."""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import psutil
import pytest

from sentinel_test_lab.core.authorization import verification_path, verify_ownership_http
from sentinel_test_lab.core.config import Settings, Thresholds
from sentinel_test_lab.core.models import Backend, RunStatus, TestConfig, TestType
from sentinel_test_lab.core.target_validator import TargetValidator
from sentinel_test_lab.core.test_orchestrator import TestOrchestrator
from sentinel_test_lab.engines.registry import engine_for
from sentinel_test_lab.integrations.cloudflare.client import CloudflareClient, CloudflareError, is_cloudflare_ip
from sentinel_test_lab.integrations.k6.adapter import K6LoadEngine, find_k6, parse_k6_event
from sentinel_test_lab.integrations.locust.adapter import find_locust
from sentinel_test_lab.integrations.process import NdjsonTail
from sentinel_test_lab.integrations.zap.client import ZapClient

pytestmark = pytest.mark.integration
FAKE_K6 = [sys.executable, str(Path(__file__).parent.parent / "support" / "fake_k6.py")]


def load(**kw) -> TestConfig:
    base = dict(test_type=TestType.LOAD, name="it", users=2, duration_s=4, rate_limit_rps=5,
                interval_s=0.0, paths=["/ok"], timeout_s=5)
    base.update(kw)
    return TestConfig(**base)


# ---------------------------------------------------------- validator
async def test_validator_inspects_local_target(server):
    result = await TargetValidator().inspect(server.url + "/")
    assert result.ok and result.status_code == 200
    assert result.ips == ["127.0.0.1"] and result.network_class == "loopback"
    assert result.response_time_ms > 0 and result.headers["server"] == "TestServer/1.0"
    assert result.tls is None and not result.errors


async def test_validator_reports_unreachable_and_invalid():
    down = await TargetValidator(timeout_s=2).inspect("http://127.0.0.1:9")
    assert not down.ok and down.errors and down.status_code is None
    bad = await TargetValidator().inspect("ftp://x")
    assert not bad.ok and bad.errors
    nx = await TargetValidator(timeout_s=3).inspect("http://no-such-host.invalid")
    assert not nx.ok and "DNS" in nx.errors[0]


async def test_ownership_verification_over_http(env, server):
    target = env.add_target(server.url)
    assert not await verify_ownership_http(target)
    server.verify_token = target.verify_token
    assert await verify_ownership_http(target)
    assert verification_path(target.verify_token) in [p for _, _, p in server.hits]


# ------------------------------------------------------------- locust
@pytest.mark.locust
async def test_locust_backend_real_run(env, server):
    if find_locust(Settings()) is None:
        pytest.skip("locust is not installed")
    target = env.add_target(server.url)
    record = await env.run(load(backend=Backend.LOCUST, duration_s=6, users=2), target)
    hits = len(server.hits_for("/ok"))
    assert record.status == RunStatus.COMPLETED and record.backend == "locust"
    assert hits > 0 and record.summary["total"] == hits
    assert hits <= 5 * 6 + 2                            # per-user throughput keeps the global cap
    assert record.summary["s2xx"] == hits and record.summary["p95_ms"] > 0
    assert record.summary["peak_users"] == 2


@pytest.mark.locust
async def test_locust_emergency_stop_kills_process_tree(env, server):
    if find_locust(Settings()) is None:
        pytest.skip("locust is not installed")
    target = env.add_target(server.url)
    prepared = env.orchestrator.prepare(load(backend=Backend.LOCUST, duration_s=60), target.id, confirmed=True)
    before = {p.pid for p in psutil.process_iter()}

    def press_stop():
        while not server.hits and time.monotonic() < deadline:
            time.sleep(0.1)
        stop_time.append(time.monotonic())
        env.orchestrator.stop(prepared)

    deadline = time.monotonic() + 30
    stop_time: list[float] = []
    threading.Thread(target=press_stop).start()
    record = await env.orchestrator.execute(prepared)
    assert record.status == RunStatus.STOPPED
    assert time.monotonic() - stop_time[0] < 5.0
    leftovers = [p for p in psutil.process_iter(["pid", "cmdline"])
                 if p.pid not in before and "sentinel_locustfile" in " ".join(p.info["cmdline"] or [])]
    assert leftovers == []
    count = len(server.hits)
    time.sleep(1.5)
    assert len(server.hits) == count


# ----------------------------------------------------------------- k6
def k6_env(env) -> None:
    env.orchestrator = TestOrchestrator(
        env.repo, env.safety, env.audit, env.paths, env.secrets,
        engine_factory=lambda c: K6LoadEngine(FAKE_K6) if c.backend == Backend.K6 else engine_for(c))


async def test_k6_adapter_stream_and_script(env, server):
    k6_env(env)
    target = env.add_target(server.url)
    record = await env.run(load(backend=Backend.K6, duration_s=3, paths=["/ok", "/error"],
                                thresholds=Thresholds(max_error_rate=1.0, max_consecutive_failures=999)), target)
    total = record.summary["total"]
    assert record.backend == "k6" and total == len(server.hits) > 0
    assert record.summary["s5xx"] == len(server.hits_for("/error")) > 0
    script = (env.paths.work_dir / "sentinel_k6_script.js").read_text(encoding="utf-8")
    assert '"rps": 5' in script and "maxRedirects: 0" in script and server.url in script


async def test_k6_adapter_enforces_budget_by_killing_process(env, server):
    k6_env(env)
    target = env.add_target(server.url)
    record = await env.run(load(backend=Backend.K6, duration_s=30, request_budget=4), target)
    assert record.summary["total"] == 4 and "ميزانية" in record.stop_reason
    assert record.summary["elapsed_s"] < 10
    assert len(server.hits) <= 6                        # at most the requests already in flight


@pytest.mark.k6
async def test_real_k6_run(env, server):
    """Runs the genuine k6 binary when it is installed (skipped otherwise)."""
    if find_k6(Settings()) is None:
        pytest.skip("k6 is not installed")
    target = env.add_target(server.url)
    record = await env.run(load(backend=Backend.K6, duration_s=6, users=2, paths=["/ok", "/secure"]), target)
    hits = len(server.hits)
    assert record.status == RunStatus.COMPLETED and record.backend == "k6", record.stop_reason
    assert hits > 0 and record.summary["total"] == hits          # every request k6 sent was counted
    assert record.summary["s2xx"] == hits and record.summary["p95_ms"] > 0
    assert hits <= 5 * 6 + 3                                      # the global rps cap held
    assert server.hits_for("/ok") and server.hits_for("/secure")
    assert record.summary["peak_users"] == 2
    assert record.details["exit_code"] == 0


@pytest.mark.k6
async def test_real_k6_emergency_stop(env, server):
    if find_k6(Settings()) is None:
        pytest.skip("k6 is not installed")
    target = env.add_target(server.url)
    prepared = env.orchestrator.prepare(load(backend=Backend.K6, duration_s=60), target.id, confirmed=True)
    stop_time: list[float] = []

    def press_stop():
        deadline = time.monotonic() + 30
        while not server.hits and time.monotonic() < deadline:
            time.sleep(0.1)
        time.sleep(1.0)
        stop_time.append(time.monotonic())
        env.orchestrator.stop(prepared)

    threading.Thread(target=press_stop).start()
    record = await env.orchestrator.execute(prepared)
    assert record.status == RunStatus.STOPPED and time.monotonic() - stop_time[0] < 5.0
    assert not [p for p in psutil.process_iter(["name", "cmdline"])
                if (p.info["name"] or "").lower() == "k6.exe" and "sentinel_k6_script" in " ".join(p.info["cmdline"] or [])]
    count = len(server.hits)
    time.sleep(1.5)
    assert len(server.hits) == count


def test_k6_missing_binary_is_reported():
    assert find_k6(Settings(k6_path="C:/nope/k6.exe")) in (None, find_k6(Settings()))


def test_parse_k6_events():
    point = lambda m, v, tags=None: {"type": "Point", "metric": m, "data": {"value": v, "tags": tags or {}}}  # noqa: E731
    assert parse_k6_event(point("http_req_duration", 12.5, {"status": "200"})) == ("request", (200, 12.5, None))
    kind, (status, _, error) = parse_k6_event(point("http_req_duration", 3.0, {"status": "0", "error": "dial: refused"}))
    assert kind == "request" and status is None and error == "dial: refused"
    assert parse_k6_event(point("vus", 7)) == ("users", 7)
    assert parse_k6_event(point("iterations", 1)) is None
    assert parse_k6_event({"type": "Metric", "metric": "vus"}) is None


def test_ndjson_tail_handles_partial_lines(tmp_path):
    path = tmp_path / "e.ndjson"
    tail = NdjsonTail(path)
    assert tail.read() == []
    path.write_bytes(b'{"a": 1}\n{"b"')
    assert tail.read() == [{"a": 1}]
    with path.open("ab") as handle:
        handle.write(b': 2}\nnot json\n[1]\n')
    assert tail.read() == [{"b": 2}]


# ---------------------------------------------------------------- zap
async def test_zap_client_version_and_auth(server):
    assert await ZapClient(server.url + "/zapapi", "test-key").version() == "2.15.0-fake"
    assert await ZapClient(server.url + "/zapapi", "wrong").version() is None
    assert await ZapClient("http://127.0.0.1:9", "x", timeout_s=2).version() is None


# --------------------------------------------------------- cloudflare
def test_cloudflare_ip_ranges():
    assert is_cloudflare_ip("104.16.1.1") and is_cloudflare_ip("2606:4700::6810:1")
    assert not is_cloudflare_ip("8.8.8.8") and not is_cloudflare_ip("not-an-ip")


async def test_cloudflare_zone_posture(server):
    client = CloudflareClient("cf-test-token", server.url + "/cfapi")
    posture = await client.zone_posture("www.example.test")
    assert posture["zone"]["name"] == "example.test"
    assert posture["settings"]["security_level"] == "low" and posture["settings"]["ssl"] == "flexible"
    assert posture["rulesets"][0]["phase"] == "http_request_sanitize"
    with pytest.raises(CloudflareError):
        await CloudflareClient("bad", server.url + "/cfapi").zone_posture("example.test")
    with pytest.raises(CloudflareError):
        await client.zone_posture("unknown.test")
