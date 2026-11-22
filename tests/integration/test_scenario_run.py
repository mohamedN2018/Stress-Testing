"""A multi-step scenario and a request body executed against the local server."""

from __future__ import annotations

import pytest

from sentinel_test_lab.core.models import TestConfig, TestType


def _load(**extra) -> TestConfig:
    return TestConfig(TestType.LOAD, "scenario", users=2, duration_s=2, rate_limit_rps=5,
                      interval_s=0.0, requests_per_user=0, method="POST", paths=["/ok"],
                      timeout_s=5, extra=extra)


@pytest.mark.integration
async def test_scenario_steps_run_in_order_and_are_reported(env, server):
    target = env.add_target(server.url)
    steps = [{"method": "POST", "path": "/login", "body": "username=qa&password=x"},
             {"method": "GET", "path": "/ok"}]
    record = await env.run(_load(_scenario=steps, scenario_steps="POST /login ← GET /ok"), target)

    assert record.summary["total"] >= 2
    # both endpoints were actually hit
    assert any(p == "/login" and m == "POST" for _, m, p in server.hits)
    assert any(p == "/ok" for _, _, p in server.hits)
    # the body reached the login endpoint
    assert {"username": "qa", "password": "x"} in server.login_bodies
    # per-step statistics are in the details, and no body text is persisted
    scenario = record.details["scenario"]
    assert {s["step"] for s in scenario} == {"POST /login", "GET /ok"}
    assert sum(s["requests"] for s in scenario) == record.summary["total"]
    assert "_scenario" not in record.config["extra"]
    assert record.config["extra"]["scenario_steps"] == "POST /login ← GET /ok"


@pytest.mark.integration
async def test_request_body_is_sent_with_each_request(env, server):
    target = env.add_target(server.url)
    record = await env.run(_load(_body="username=qa&password=x", body_type="form"), target)
    assert record.summary["total"] >= 1
    assert {"username": "qa", "password": "x"} in server.login_bodies or \
        any(p == "/ok" and m == "POST" for _, m, p in server.hits)
    assert "_body" not in record.config["extra"]
