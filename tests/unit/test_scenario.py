"""Scenario parsing and request-body validation."""

from __future__ import annotations

import pytest

from sentinel_test_lab.core.models import Backend, TestConfig, TestType
from sentinel_test_lab.core.safety_manager import SafetyViolation
from sentinel_test_lab.core.scenario import (
    MAX_BODY_BYTES,
    body_type_of,
    describe_steps,
    parse_scenario,
    steps_from_extra,
)


def test_body_type_detection():
    assert body_type_of('{"a": 1}') == "json"
    assert body_type_of("[1,2]") == "json"
    assert body_type_of("a=b&c=d") == "form"
    assert body_type_of("just text") == "text"
    assert body_type_of("   ") == ""


def test_parse_scenario_ok():
    steps = parse_scenario("# login flow\nPOST /login u=a&p=b\nGET /dash\n\nPOST /api {\"x\": 1}")
    assert [s.method for s in steps] == ["POST", "GET", "POST"]
    assert steps[0].body_type == "form" and steps[2].body_type == "json"
    assert describe_steps(steps) == "POST /login ← GET /dash ← POST /api"


@pytest.mark.parametrize("text", [
    "GET",                       # no path
    "FETCH /x",                  # bad method
    "GET not-a-path",            # path must start with /
    "GET /x body-not-allowed",   # GET carries no body
    "\n".join(f"GET /{i}" for i in range(11)),  # too many steps
])
def test_parse_scenario_rejects(text):
    with pytest.raises(ValueError):
        parse_scenario(text)


def test_steps_from_extra_roundtrip():
    steps = parse_scenario("POST /login u=a")
    extra = {"_scenario": [s.to_dict() for s in steps]}
    assert steps_from_extra(extra)[0].path == "/login"
    assert steps_from_extra({})[0:] == []


def _cfg(backend: Backend = Backend.INTERNAL, **extra) -> TestConfig:
    return TestConfig(TestType.LOAD, "s", users=1, duration_s=2, rate_limit_rps=5,
                      interval_s=0.0, paths=["/ok"], timeout_s=5, method="POST",
                      backend=backend, extra=extra)


def test_body_requires_trusted_target(env):
    from sentinel_test_lab.core.models import Environment
    public = env.add_target("http://93.184.216.34", ips=["93.184.216.34"],
                            environment=Environment.PRODUCTION, allow_private=False, name="public")
    assert not public.is_trusted
    with pytest.raises(SafetyViolation):
        env.safety.authorize_run(_cfg(_body="username=a&password=b"), public,
                                 confirmed=True, elevated_confirmation="")


def test_body_too_big_rejected(env):
    target = env.add_target("http://127.0.0.1:8000")
    with pytest.raises(SafetyViolation):
        env.safety.authorize_run(_cfg(_body="x" * (MAX_BODY_BYTES + 1)), target,
                                 confirmed=True, elevated_confirmation="")


def test_body_only_internal_engine(env):
    target = env.add_target("http://127.0.0.1:8000")
    with pytest.raises(SafetyViolation):
        env.safety.authorize_run(_cfg(Backend.LOCUST, _body="a=b"), target,
                                 confirmed=True, elevated_confirmation="")


def test_scenario_step_out_of_scope_rejected(env):
    target = env.add_target("http://127.0.0.1:8000", allowed_paths=["/ok"])
    cfg = _cfg(_scenario=[{"method": "GET", "path": "/secret"}])
    with pytest.raises(SafetyViolation):
        env.safety.authorize_run(cfg, target, confirmed=True, elevated_confirmation="")


def test_valid_scenario_authorized(env):
    target = env.add_target("http://127.0.0.1:8000")
    cfg = _cfg(_scenario=[{"method": "POST", "path": "/login", "body": "u=a"},
                          {"method": "GET", "path": "/ok"}])
    approved = env.safety.authorize_run(cfg, target, confirmed=True, elevated_confirmation="")
    assert approved.request_budget > 0
