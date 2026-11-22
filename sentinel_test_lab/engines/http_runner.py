"""Shared HTTP execution: scoped single requests and the virtual-user load runner.

Every request goes through :class:`RunGuard` (budget + global rate limit) and
is recorded in the :class:`MetricsCollector`, so all engines inherit the same
safety limits and produce real measurements.
"""

from __future__ import annotations

import asyncio
import itertools
import time
from typing import Any, Awaitable, Callable

import httpx

from ..core.authorization import ensure_request_in_scope
from ..core.models import LoadStage
from ..core.safety_manager import peak_users
from ..core.scenario import BODY_METHODS, CONTENT_TYPES, Step, body_type_of, steps_from_extra
from .base import EngineContext

ResponseHook = Callable[[httpx.Response | None, int], None]


def error_kind(exc: BaseException) -> str:
    if isinstance(exc, httpx.TimeoutException):
        return "timeout"
    if isinstance(exc, httpx.ConnectError):
        return "connect_error"
    if isinstance(exc, httpx.RemoteProtocolError):
        return "protocol_error"
    return type(exc).__name__


def body_kwargs(body: str, body_type: str = "") -> dict[str, Any]:
    """httpx keyword arguments that send ``body`` with the matching Content-Type."""
    if not body:
        return {}
    kind = body_type or body_type_of(body) or "text"
    return {"content": body.encode("utf-8"), "headers": {"Content-Type": CONTENT_TYPES[kind]}}


class ScopedHttp:
    """Sends individual in-scope requests for the assessment engines."""

    def __init__(self, ctx: EngineContext, client: httpx.AsyncClient) -> None:
        self._ctx = ctx
        self._client = client

    async def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response | None:
        """Return the response, or None when stopped, out of budget or on transport error.

        Raises :class:`ScopeError` if the request is outside the authorized scope.
        """
        ctx = self._ctx
        path = ensure_request_in_scope(ctx.target, method, path)
        if not await ctx.guard.acquire():
            return None
        started = time.perf_counter()
        try:
            response = await self._client.request(method, path, **kwargs)
        except asyncio.CancelledError:
            ctx.metrics.record_aborted()
            raise
        except httpx.HTTPError as exc:
            ctx.metrics.record(None, (time.perf_counter() - started) * 1000, error_kind(exc))
            return None
        ctx.metrics.record(response.status_code, (time.perf_counter() - started) * 1000)
        return response


class HttpRunner:
    """Closed-model load generator: N virtual users following a list of stages."""

    TICK_S = 0.05

    def __init__(self, ctx: EngineContext, on_response: ResponseHook | None = None) -> None:
        self._ctx = ctx
        self._on_response = on_response
        self._paths = itertools.cycle(ctx.config.paths or ["/"])
        self._request_index = itertools.count(1)
        self._tasks: list[asyncio.Task[None]] = []
        self._client: httpx.AsyncClient | None = None
        extra = ctx.config.extra
        self._body = body_kwargs(str(extra.get("_body") or ""), str(extra.get("body_type") or ""))
        self._steps: list[Step] = steps_from_extra(extra)
        self._step_stats = [{"requests": 0, "ok": 0, "failed": 0, "total_ms": 0.0} for _ in self._steps]

    async def __aenter__(self) -> "HttpRunner":
        peak = max(peak_users(self._ctx.config), 1)
        self._client = self._ctx.new_client(max_connections=peak)
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self._set_users(0)
        if self._client is not None:
            await self._client.aclose()
        self._ctx.metrics.set_users(0)
        if self._steps:
            self._ctx.extra_details["scenario"] = [
                {"step": step.label.partition("?")[0], "requests": stats["requests"], "ok": stats["ok"],
                 "failed": stats["failed"],
                 "avg_ms": round(stats["total_ms"] / stats["requests"], 1) if stats["requests"] else None}
                for step, stats in zip(self._steps, self._step_stats)]

    # ------------------------------------------------------------------ stages
    async def run_stage(self, stage: LoadStage, previous_users: int = 0) -> bool:
        """Run one stage. Returns False when the run was stopped during the stage."""
        ctx = self._ctx
        if stage.label:
            ctx.metrics.set_phase(stage.label)
        started = time.monotonic()
        while True:
            if ctx.guard.stopped:
                return False
            if ctx.guard.exhausted:
                # budget used up: let the reserved in-flight requests finish, then close
                while not ctx.guard.stopped and any(not t.done() for t in self._tasks):
                    await asyncio.sleep(self.TICK_S)
                ctx.guard.budget_stop()
                return False
            elapsed = time.monotonic() - started
            if elapsed >= stage.duration_s:
                break
            if stage.ramp and stage.duration_s > 0:
                fraction = min(1.0, elapsed / stage.duration_s)
                desired = round(previous_users + (stage.users - previous_users) * fraction)
                desired = max(desired, 1 if stage.users > 0 else 0)
            else:
                desired = stage.users
            await self._set_users(desired)
            if not stage.ramp and self._all_done():
                break  # every user finished its request quota
            await asyncio.sleep(min(self.TICK_S, max(0.0, stage.duration_s - elapsed)))
        return not ctx.guard.stopped

    async def run_stages(
        self,
        stages: list[LoadStage],
        after_stage: Callable[[LoadStage], Awaitable[bool]] | None = None,
    ) -> None:
        previous = 0
        for stage in stages:
            if not await self.run_stage(stage, previous):
                break
            previous = stage.users
            if after_stage is not None and not await after_stage(stage):
                break

    def _all_done(self) -> bool:
        return bool(self._tasks) and all(t.done() for t in self._tasks)

    async def _set_users(self, desired: int) -> None:
        active = [t for t in self._tasks if not t.done()]
        finished_quota = len(self._tasks) - len(active)
        if self._ctx.config.requests_per_user > 0:
            # users that completed their quota are not replaced
            desired = max(0, desired - finished_quota)
        while len(active) < desired:
            task = asyncio.create_task(self._virtual_user())
            self._tasks.append(task)
            active.append(task)
        if len(active) > desired:
            surplus = active[desired:]
            for task in surplus:
                task.cancel()
            await asyncio.gather(*surplus, return_exceptions=True)
            self._tasks = [t for t in self._tasks if t not in surplus]
            active = active[:desired]
        self._ctx.metrics.set_users(len(active))

    # ------------------------------------------------------------ virtual user
    async def _virtual_user(self) -> None:
        ctx = self._ctx
        config = ctx.config
        assert self._client is not None
        if self._steps:
            await self._scenario_user()
            return
        sent = 0
        while not ctx.guard.stopped:
            if config.requests_per_user and sent >= config.requests_per_user:
                return
            if not await ctx.guard.acquire():
                return
            path = next(self._paths)
            index = next(self._request_index)
            started = time.perf_counter()
            response: httpx.Response | None = None
            try:
                response = await self._client.request(config.method, path, **self._body)
                ctx.metrics.record(response.status_code, (time.perf_counter() - started) * 1000)
            except asyncio.CancelledError:
                ctx.metrics.record_aborted()
                raise
            except httpx.HTTPError as exc:
                ctx.metrics.record(None, (time.perf_counter() - started) * 1000, error_kind(exc))
            sent += 1
            if self._on_response is not None:
                self._on_response(response, index)
            if config.interval_s > 0:
                await asyncio.sleep(config.interval_s)

    async def _scenario_user(self) -> None:
        """One user repeating the scenario steps in order, with its own cookie jar.

        For write steps the Django-style ``csrftoken`` cookie (if the site set one) is
        echoed in ``X-CSRFToken``, as a browser's JavaScript would do.
        """
        ctx = self._ctx
        config = ctx.config
        client = ctx.new_client(max_connections=1)
        sent = 0
        try:
            while not ctx.guard.stopped:
                for position, step in enumerate(self._steps):
                    if config.requests_per_user and sent >= config.requests_per_user:
                        return
                    if not await ctx.guard.acquire():
                        return
                    kwargs = body_kwargs(step.body, step.body_type)
                    headers = dict(kwargs.pop("headers", {}))
                    if step.method in BODY_METHODS:
                        try:
                            token = client.cookies.get("csrftoken")
                        except httpx.CookieConflict:
                            token = None
                        if token:
                            headers["X-CSRFToken"] = token
                            headers["Referer"] = ctx.target.base_url + step.path
                    index = next(self._request_index)
                    stats = self._step_stats[position]
                    started = time.perf_counter()
                    response: httpx.Response | None = None
                    try:
                        response = await client.request(step.method, step.path, headers=headers, **kwargs)
                        elapsed = (time.perf_counter() - started) * 1000
                        ctx.metrics.record(response.status_code, elapsed)
                    except asyncio.CancelledError:
                        ctx.metrics.record_aborted()
                        raise
                    except httpx.HTTPError as exc:
                        elapsed = (time.perf_counter() - started) * 1000
                        ctx.metrics.record(None, elapsed, error_kind(exc))
                    stats["requests"] += 1
                    stats["total_ms"] += elapsed
                    stats["ok" if response is not None and response.status_code < 400 else "failed"] += 1
                    sent += 1
                    if self._on_response is not None:
                        self._on_response(response, index)
                    if config.interval_s > 0:
                        await asyncio.sleep(config.interval_s)
        finally:
            await client.aclose()
