"""TLS checks against a real local HTTPS server, and DNS-based checks against a local DNS server."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from sentinel_test_lab.core import dns_lookup
from sentinel_test_lab.core.authorization import (
    build_target,
    verification_txt_value,
    verify_ownership_dns,
)
from sentinel_test_lab.core.config import Thresholds
from sentinel_test_lab.core.models import Environment, RunStatus, Severity, TestConfig, TestType
from sentinel_test_lab.core.target_validator import TargetValidator
from sentinel_test_lab.engines.resilience.ddos_posture import DdosPostureEngine
from tests.support.certs import make_server_context
from tests.support.fake_dns import FakeDnsServer
from tests.support.local_server import LocalTestServer

pytestmark = pytest.mark.integration


@pytest.fixture()
def https_server(tmp_path, request):
    options = getattr(request, "param", {})
    server = LocalTestServer(ssl_context=make_server_context(tmp_path / "tls", **options)).start()
    yield server
    server.stop()


@pytest.fixture()
def fake_dns():
    servers: list[FakeDnsServer] = []

    def start(records):
        server = FakeDnsServer(records)
        servers.append(server)
        dns_lookup.use_nameservers(["127.0.0.1"], server.port)
        return server

    yield start
    dns_lookup.use_nameservers(None)
    for server in servers:
        server.stop()


def security(paths=("/",)) -> TestConfig:
    return TestConfig(TestType.SECURITY, "tls", users=1, duration_s=30, rate_limit_rps=5,
                      interval_s=0.0, paths=list(paths), timeout_s=5)


def titles(record) -> str:
    return " | ".join(f.title for f in record.findings)


# ------------------------------------------------------------------- TLS
async def test_validator_reads_certificate_of_https_target(https_server):
    result = await TargetValidator(timeout_s=5).inspect(https_server.url, verify_tls=False)
    assert result.ok and result.scheme == "https" and result.status_code == 200
    tls = result.tls
    assert tls.available and tls.trusted is False and tls.trust_error
    assert tls.protocol in ("TLSv1.2", "TLSv1.3") and tls.cipher
    assert tls.subject == "sentinel-local-test" and tls.issuer == "sentinel-local-test"
    assert "localhost" in tls.san and 28 <= tls.days_remaining <= 30


async def test_validator_refuses_untrusted_certificate_by_default(https_server):
    result = await TargetValidator(timeout_s=5).inspect(https_server.url)   # verify_tls=True
    assert not result.ok and result.status_code is None
    assert result.tls.available and result.tls.trusted is False              # still inspected and reported


async def test_security_assessment_reports_untrusted_certificate(env, https_server):
    target = env.add_target(https_server.url, verify_tls=False)
    record = await env.run(security(), target)
    tls = record.details["tls"]
    assert record.status == RunStatus.COMPLETED
    assert tls["available"] and tls["trusted"] is False and tls["protocol"].startswith("TLSv1.")
    assert set(tls["legacy_protocols"]) == {"TLS 1.0", "TLS 1.1"}
    assert all(accepted in (False, None) for accepted in tls["legacy_protocols"].values())
    untrusted = next(f for f in record.findings if "غير موثوقة" in f.title)
    assert untrusted.severity == Severity.HIGH
    assert "Strict-Transport-Security" in titles(record)      # HSTS is required on HTTPS
    assert "HTTP بدون تشفير" not in titles(record)
    assert "تنتهي قريباً" not in titles(record) and "منتهية" not in titles(record)


@pytest.mark.parametrize("https_server", [{"days_valid": 10}], indirect=True)
async def test_security_assessment_warns_before_certificate_expiry(env, https_server):
    target = env.add_target(https_server.url, verify_tls=False)
    record = await env.run(security(), target)
    finding = next(f for f in record.findings if "تنتهي قريباً" in f.title)
    assert finding.severity == Severity.MEDIUM and 8 <= record.details["tls"]["days_remaining"] <= 10


@pytest.mark.parametrize("https_server", [{"expired": True}], indirect=True)
async def test_security_assessment_reports_expired_certificate(env, https_server):
    target = env.add_target(https_server.url, verify_tls=False)
    record = await env.run(security(), target)
    finding = next(f for f in record.findings if "منتهية الصلاحية" in f.title)
    assert finding.severity == Severity.HIGH and record.details["tls"]["days_remaining"] < 0


async def test_load_over_https_and_certificate_verification(env, https_server):
    config = dict(users=2, duration_s=3, rate_limit_rps=5, interval_s=0.0, paths=["/ok"], timeout_s=5)
    trusted_off = env.add_target(https_server.url, verify_tls=False)
    record = await env.run(TestConfig(TestType.LOAD, "https", **config), trusted_off)
    assert record.summary["s2xx"] == record.summary["total"] == len(https_server.hits_for("/ok")) > 0

    https_server.reset()
    strict = env.add_target(https_server.url, verify_tls=True)      # same URL: updates the stored target
    thresholds = Thresholds(max_consecutive_failures=3, min_samples=1000)
    record = await env.run(TestConfig(TestType.LOAD, "https", thresholds=thresholds, **config), strict)
    assert record.status == RunStatus.AUTO_STOPPED               # untrusted certificate is never accepted silently
    assert record.summary["success"] == 0 and record.summary["transport_errors"] >= 3
    assert https_server.hits == []


# ------------------------------------------------------------------- DNS
def public_target(host="shop.test", ips=("104.16.1.1",)):
    return build_target(url=f"https://{host}", name="shop", environment=Environment.PRODUCTION,
                        authorization_statement="I own this domain", confirmed=True,
                        resolved_ips=list(ips))


async def test_ownership_verification_over_dns_txt(fake_dns):
    target = public_target()
    server = fake_dns({("_sentinel-verify.shop.test", "TXT"): ['"sentinel-verify=wrong-token"']})
    assert not await verify_ownership_dns(target, timeout_s=3)
    assert ("_sentinel-verify.shop.test", "TXT") in server.queries and ("shop.test", "TXT") in server.queries

    fake_dns({("_sentinel-verify.shop.test", "TXT"): [f'"{verification_txt_value(target.verify_token)}"']})
    assert await verify_ownership_dns(target, timeout_s=3)

    fake_dns({("shop.test", "TXT"): ['"v=spf1 -all"', f'"{verification_txt_value(target.verify_token)}"']})
    assert await verify_ownership_dns(target, timeout_s=3)      # also accepted on the domain itself


async def test_ownership_verification_fails_without_dns_answer(fake_dns):
    fake_dns({})
    assert not await verify_ownership_dns(public_target(), timeout_s=3)


async def test_ddos_posture_flags_origin_exposure_in_dns(fake_dns):
    target = public_target("www.shop.test")
    fake_dns({
        ("shop.test", "NS"): ["amy.ns.cloudflare.com.", "bob.ns.cloudflare.com."],
        ("origin.shop.test", "A"): ["93.184.216.34"],          # public, outside the CDN network
        ("dev.shop.test", "A"): ["104.16.9.9"],                # behind the CDN: fine
        ("ftp.shop.test", "A"): ["10.0.0.5"],                  # private address: not an exposure
        ("shop.test", "MX"): ["10 mail.shop.test."],
        ("mail.shop.test", "A"): ["93.184.216.35"],
    })
    ctx = SimpleNamespace(target=target, guard=SimpleNamespace(stopped=False))
    findings, details = [], {}
    await DdosPostureEngine()._dns_checks(ctx, True, findings, details)
    exposed = {(e["name"], e["ip"]) for e in details["origin_exposure_indicators"]}
    assert exposed == {("origin.shop.test", "93.184.216.34"), ("mail.shop.test", "93.184.216.35")}
    assert sorted(details["nameservers"]) == ["amy.ns.cloudflare.com", "bob.ns.cloudflare.com"]  # DNS order is not fixed
    assert len(findings) == 1 and findings[0].severity == Severity.MEDIUM and "origin.shop.test" in findings[0].detail


async def test_ddos_posture_without_cdn_skips_origin_lookup(fake_dns):
    server = fake_dns({("shop.test", "NS"): ["ns1.host.test."]})
    ctx = SimpleNamespace(target=public_target("shop.test", ["93.184.216.34"]), guard=SimpleNamespace(stopped=False))
    findings, details = [], {}
    await DdosPostureEngine()._dns_checks(ctx, False, findings, details)
    assert details["origin_exposure_indicators"] == [] and findings == []
    assert server.queries == [("shop.test", "NS")]              # no subdomain probing when there is no CDN
