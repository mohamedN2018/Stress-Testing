from __future__ import annotations

import pytest

from sentinel_test_lab.core.authorization import (
    ScopeError,
    TargetError,
    build_target,
    classify_ip,
    classify_ips,
    ensure_request_in_scope,
    normalize_path,
    parse_target_url,
    path_allowed,
)
from sentinel_test_lab.core.models import Environment

STATEMENT = "I am the owner of this site"


def make(url="https://example.com", ips=("93.184.216.34",), **kw):
    params = dict(url=url, name="t", environment=Environment.PRODUCTION,
                  authorization_statement=STATEMENT, confirmed=True, resolved_ips=list(ips))
    params.update(kw)
    return build_target(**params)


@pytest.mark.parametrize("url,scheme,host,port", [
    ("https://example.com", "https", "example.com", 443),
    ("example.com", "https", "example.com", 443),
    ("http://Example.COM:8080/path", "http", "example.com", 8080),
    ("http://127.0.0.1:8000", "http", "127.0.0.1", 8000),
    ("http://[::1]:9000/", "http", "::1", 9000),
])
def test_parse_valid_urls(url, scheme, host, port):
    parsed = parse_target_url(url)
    assert (parsed.scheme, parsed.host, parsed.port) == (scheme, host, port)


@pytest.mark.parametrize("url", [
    "", "ftp://example.com", "https://user:pass@example.com", "https://", "http://exa mple.com",
    "https://-bad-.com", "http://example.com:99999",
])
def test_parse_invalid_urls(url):
    with pytest.raises(TargetError):
        parse_target_url(url)


def test_base_url_omits_default_port():
    assert parse_target_url("https://example.com:443/x").base_url == "https://example.com"
    assert parse_target_url("http://example.com:8080").base_url == "http://example.com:8080"
    assert parse_target_url("http://[::1]:9000").base_url == "http://[::1]:9000"


@pytest.mark.parametrize("ip,expected", [
    ("127.0.0.1", "loopback"), ("::1", "loopback"), ("10.0.0.5", "private"),
    ("192.168.1.10", "private"), ("172.16.0.1", "private"), ("169.254.169.254", "private"),
    ("100.64.0.1", "private"), ("fd00::1", "private"), ("::ffff:10.0.0.1", "private"),
    ("0.0.0.0", "private"), ("8.8.8.8", "public"), ("2606:4700::1111", "public"),
])
def test_classify_ip(ip, expected):
    assert classify_ip(ip) == expected


def test_mixed_resolution_is_rejected():
    with pytest.raises(ScopeError):
        classify_ips(["8.8.8.8", "10.0.0.1"])


def test_authorization_confirmation_is_required():
    with pytest.raises(ScopeError):
        make(confirmed=False)


def test_authorization_statement_is_required():
    with pytest.raises(ScopeError):
        make(authorization_statement="  ")


def test_private_target_needs_explicit_scope():
    with pytest.raises(ScopeError):
        make(url="http://192.168.1.20", ips=["192.168.1.20"])
    with pytest.raises(ScopeError):
        make(url="http://localhost:8000", ips=["127.0.0.1"])


def test_private_target_allowed_with_explicit_scope():
    target = make(url="http://localhost:8000", ips=["127.0.0.1"], allow_private=True,
                  environment=Environment.LOCALHOST)
    assert target.network_class == "loopback" and target.allow_private and target.is_trusted


def test_lan_target_is_not_trusted_without_ownership_proof():
    target = make(url="http://192.168.1.20", ips=["192.168.1.20"], allow_private=True,
                  environment=Environment.STAGING)
    assert target.network_class == "private"
    assert not target.is_trusted


def test_public_target_is_untrusted_and_never_private():
    target = make(allow_private=True)
    assert target.network_class == "public"
    assert not target.allow_private and not target.is_trusted
    assert len(target.verify_token) == 32


def test_localhost_environment_rejected_for_public_ip():
    with pytest.raises(ScopeError):
        make(environment=Environment.LOCALHOST)


def test_unknown_method_rejected():
    with pytest.raises(TargetError):
        make(allowed_methods=["GET", "TRACE"])


@pytest.mark.parametrize("path", ["http://evil.test/", "//evil.test/x", "/a/../../etc", "\\\\host\\x"])
def test_normalize_path_rejects_escapes(path):
    with pytest.raises(ScopeError):
        normalize_path(path)


def test_path_scope():
    target = make(allowed_paths=["/api", "/health"])
    assert path_allowed(target, "/api")
    assert path_allowed(target, "/api/users?page=2")
    assert path_allowed(target, "/health")
    assert not path_allowed(target, "/apix")
    assert not path_allowed(target, "/admin")
    assert not path_allowed(target, "/api/../admin")


def test_request_scope_enforces_method_and_path():
    target = make(allowed_paths=["/api"], allowed_methods=["GET"])
    assert ensure_request_in_scope(target, "get", "/api/x") == "/api/x"
    with pytest.raises(ScopeError):
        ensure_request_in_scope(target, "POST", "/api/x")
    with pytest.raises(ScopeError):
        ensure_request_in_scope(target, "GET", "/other")
