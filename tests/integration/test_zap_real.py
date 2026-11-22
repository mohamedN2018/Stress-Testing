"""OWASP ZAP integration against a genuine local ZAP installation (skipped when ZAP is absent)."""

from __future__ import annotations

import psutil
import pytest

from sentinel_test_lab.core.models import RunStatus, TestConfig, TestType
from sentinel_test_lab.integrations.zap.client import ZapClient
from sentinel_test_lab.integrations.zap.daemon import ZapDaemon, local_daemon

pytestmark = [pytest.mark.integration, pytest.mark.zap]


@pytest.fixture(scope="module")
def zap(tmp_path_factory):
    reason = ZapDaemon.unavailable_reason()
    if reason:
        pytest.skip(reason)
    daemon = local_daemon()
    import asyncio

    asyncio.run(daemon.ensure_running(tmp_path_factory.mktemp("zap-home")))
    yield daemon
    pid = daemon._process.pid  # noqa: SLF001
    daemon.stop()
    assert not psutil.pid_exists(pid) or psutil.Process(pid).status() == psutil.STATUS_ZOMBIE


def security(**extra) -> TestConfig:
    return TestConfig(TestType.SECURITY, "zap", users=1, duration_s=60, rate_limit_rps=5,
                      interval_s=0.0, paths=["/"], timeout_s=5, extra={"use_zap": True, **extra})


async def test_daemon_is_private_and_keyed(zap):
    assert zap.running and zap.url.startswith("http://127.0.0.1:") and len(zap.api_key) == 32
    assert await ZapClient(zap.url, zap.api_key).version() == zap.version
    assert await ZapClient(zap.url, "wrong-key", timeout_s=5).version() is None   # API key is enforced


async def test_real_zap_passive_scan(env, server, zap):
    target = env.add_target(server.url)
    record = await env.run(security(), target)
    info = record.details["zap"]
    assert record.status == RunStatus.COMPLETED, record.stop_reason
    assert info["status"] == "تم" and info["mode"] == "passive" and info["source"] == "local-daemon"
    assert info["version"] == zap.version and info["alerts"] >= 1
    zap_findings = [f for f in record.findings if f.category == "zap"]
    assert zap_findings and all(f.title.startswith("ZAP: ") for f in zap_findings)
    text = " | ".join(f.title for f in zap_findings).lower()
    assert "header" in text or "cookie" in text       # the weak local page has both kinds of issue
    assert not any(p in ("/admin", "/etc/passwd") for _, _, p in server.hits)


async def test_real_zap_active_scan_stays_on_the_given_url(env, server, zap):
    target = env.add_target(server.url)
    server.reset()
    record = await env.run(security(active_scan=True, active_scan_confirmed=True), target)
    info = record.details["zap"]
    assert record.status == RunStatus.COMPLETED, record.stop_reason
    assert info["mode"] == "active" and info["status"] == "تم"
    methods = {m for _, m, _ in server.hits}
    assert methods <= {"GET", "HEAD", "POST", "OPTIONS", "TRACE", "PUT", "DELETE", "PATCH", "CONNECT"}
    assert len(server.hits) < 3000                    # bounded: one URL, no recursion
