"""Local HTTP server used by the integration tests and the example report.

It runs in a background thread on 127.0.0.1 and offers endpoints with known
behaviour (rate limiting, lockout, degradation under concurrency, weak/strong
security headers) plus minimal fakes of the ZAP and Cloudflare APIs.

Run standalone:  python -m tests.support.local_server [port]
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any

from aiohttp import web

SECURE_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=()",
}
LOGIN_FORM = """<html><body><form method="post">
<input type="hidden" name="csrfmiddlewaretoken" value="tok-123">
<input name="username"><input name="password" type="password"></form></body></html>"""


class LocalTestServer:
    def __init__(self, port: int = 0, verify_token: str = "", rate_limit_after: int = 10,
                 lockout_after: int = 5, degrade_limit: int = 12, ssl_context: Any = None,
                 host: str = "127.0.0.1") -> None:
        self._requested_port = port
        self._ssl_context = ssl_context
        self._host = host
        self.verify_token = verify_token
        self.rate_limit_after = rate_limit_after
        self.lockout_after = lockout_after
        self.degrade_limit = degrade_limit
        self.port = 0
        self.hits: list[tuple[float, str, str]] = []
        self.max_concurrency = 0
        self.login_bodies: list[dict[str, str]] = []
        self.zap_calls: list[str] = []
        self._concurrent = 0
        self._degrade_concurrent = 0
        self._rate_count = 0
        self._failed_logins = 0
        self._flaky = 0
        self._zap_pending = 2
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._ready = threading.Event()
        self._runner: web.AppRunner | None = None

    # ------------------------------------------------------------- lifecycle
    @property
    def url(self) -> str:
        scheme = "https" if self._ssl_context is not None else "http"
        return f"{scheme}://127.0.0.1:{self.port}"

    def start(self) -> "LocalTestServer":
        self._thread = threading.Thread(target=self._serve, name="local-test-server", daemon=True)
        self._thread.start()
        if not self._ready.wait(10):
            raise RuntimeError("local test server did not start")
        return self

    def stop(self) -> None:
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            self._thread.join(5)

    def reset(self) -> None:
        self.hits.clear()
        self.login_bodies.clear()
        self.zap_calls.clear()
        self.max_concurrency = 0
        self._rate_count = self._failed_logins = self._flaky = 0
        self._zap_pending = 2

    def hits_for(self, path: str) -> list[float]:
        return [t for t, _, p in self.hits if p == path]

    def _serve(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        self._runner = web.AppRunner(self._build_app(), access_log=None)
        loop.run_until_complete(self._runner.setup())
        site = web.TCPSite(self._runner, self._host, self._requested_port, ssl_context=self._ssl_context)
        loop.run_until_complete(site.start())
        self.port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
        self._ready.set()
        try:
            loop.run_forever()
        finally:
            loop.run_until_complete(self._runner.cleanup())
            loop.close()

    # ------------------------------------------------------------------ app
    def _build_app(self) -> web.Application:
        @web.middleware
        async def track(request: web.Request, handler: Any) -> web.StreamResponse:
            self.hits.append((time.monotonic(), request.method, request.path))
            self._concurrent += 1
            self.max_concurrency = max(self.max_concurrency, self._concurrent)
            try:
                return await handler(request)
            finally:
                self._concurrent -= 1

        app = web.Application(middlewares=[track])
        r = app.router
        r.add_get("/", self.index)
        r.add_get("/ok", self.ok)
        r.add_post("/ok", self.ok)
        r.add_get("/slow", self.slow)
        r.add_get("/error", self.error)
        r.add_get("/flaky", self.flaky)
        r.add_get("/ratelimited", self.ratelimited)
        r.add_get("/degrade", self.degrade)
        r.add_get("/secure", self.secure)
        r.add_get("/redirect", self.redirect)
        r.add_get("/login", self.login_page)
        r.add_post("/login", self.login)
        r.add_get("/login-open", self.login_page)
        r.add_post("/login-open", self.login_open)
        r.add_get("/.well-known/{name}", self.well_known)
        r.add_get("/zapapi/JSON/{component}/{kind}/{name}/", self.zap)
        r.add_get("/cfapi/zones", self.cf_zones)
        r.add_get("/cfapi/zones/{zone}/settings/{setting}", self.cf_setting)
        r.add_get("/cfapi/zones/{zone}/rulesets", self.cf_rulesets)
        return app

    async def index(self, request: web.Request) -> web.Response:
        response = web.Response(text="<html><body><h1>Local test site</h1></body></html>",
                                content_type="text/html",
                                headers={"Server": "TestServer/1.0", "X-Powered-By": "TestStack 2.3"})
        response.headers.add("Set-Cookie", "sessionid=abc123; Path=/")
        if request.headers.get("Origin"):
            response.headers["Access-Control-Allow-Origin"] = request.headers["Origin"]
            response.headers["Access-Control-Allow-Credentials"] = "true"
        return response

    async def ok(self, request: web.Request) -> web.Response:
        return web.Response(text="ok")

    async def slow(self, request: web.Request) -> web.Response:
        await asyncio.sleep(float(request.query.get("ms", "200")) / 1000)
        return web.Response(text="slow")

    async def error(self, request: web.Request) -> web.Response:
        return web.Response(status=500, text="boom")

    async def flaky(self, request: web.Request) -> web.Response:
        self._flaky += 1
        return web.Response(status=500 if self._flaky % 2 == 0 else 200, text="flaky")

    async def ratelimited(self, request: web.Request) -> web.Response:
        self._rate_count += 1
        if self._rate_count > self.rate_limit_after:
            return web.Response(status=429, text="Too Many Requests", headers={"Retry-After": "30"})
        remaining = self.rate_limit_after - self._rate_count
        return web.Response(text="ok", headers={"X-RateLimit-Limit": str(self.rate_limit_after),
                                                "X-RateLimit-Remaining": str(remaining)})

    async def degrade(self, request: web.Request) -> web.Response:
        """Latency grows with concurrency; overload beyond ``degrade_limit``."""
        self._degrade_concurrent += 1
        try:
            n = self._degrade_concurrent
            if n > self.degrade_limit:
                return web.Response(status=503, text="overloaded")
            await asyncio.sleep(0.01 * n)
            return web.Response(text="ok")
        finally:
            self._degrade_concurrent -= 1

    async def secure(self, request: web.Request) -> web.Response:
        response = web.Response(text="<html><body>secure</body></html>", content_type="text/html",
                                headers=SECURE_HEADERS)
        response.headers.add("Set-Cookie", "sessionid=abc; Path=/; HttpOnly; Secure; SameSite=Lax")
        return response

    async def redirect(self, request: web.Request) -> web.Response:
        return web.Response(status=302, headers={"Location": "http://203.0.113.10/elsewhere"})

    async def login_page(self, request: web.Request) -> web.Response:
        return web.Response(text=LOGIN_FORM, content_type="text/html")

    async def login(self, request: web.Request) -> web.Response:
        self.login_bodies.append(dict(await request.post()))
        self._failed_logins += 1
        if self._failed_logins > self.lockout_after:
            return web.Response(status=429, text="Too many attempts. Account temporarily locked.",
                                headers={"Retry-After": "300"})
        return web.Response(status=401, text=LOGIN_FORM, content_type="text/html")

    async def login_open(self, request: web.Request) -> web.Response:
        self.login_bodies.append(dict(await request.post()))
        return web.Response(status=401, text=LOGIN_FORM, content_type="text/html")

    async def well_known(self, request: web.Request) -> web.Response:
        name = request.match_info["name"]
        if self.verify_token and name == f"sentinel-verify-{self.verify_token}.txt":
            return web.Response(text=self.verify_token)
        if name == "security.txt":
            return web.Response(text="Contact: mailto:security@example.test\n")
        return web.Response(status=404, text="not found")

    # -------------------------------------------------------------- fake ZAP
    async def zap(self, request: web.Request) -> web.Response:
        if request.headers.get("X-ZAP-API-Key") != "test-key":
            return web.json_response({"code": "bad_api_key"}, status=401)
        info = request.match_info
        call = f"{info['component']}/{info['kind']}/{info['name']}"
        self.zap_calls.append(call)
        if call == "core/view/version":
            return web.json_response({"version": "2.15.0-fake"})
        if call == "pscan/view/recordsToScan":
            self._zap_pending = max(0, self._zap_pending - 1)
            return web.json_response({"recordsToScan": str(self._zap_pending)})
        if call == "core/view/alerts":
            return web.json_response({"alerts": [
                {"alert": "X-Content-Type-Options Header Missing", "risk": "Low",
                 "description": "desc", "solution": "set nosniff", "url": request.query.get("baseurl", ""),
                 "evidence": ""},
                {"alert": "Cookie No HttpOnly Flag", "risk": "Medium", "description": "d",
                 "solution": "s", "url": "u", "evidence": "Set-Cookie: sessionid"},
            ]})
        if call == "ascan/action/scan":
            return web.json_response({"scan": "7"})
        if call == "ascan/view/status":
            return web.json_response({"status": "100"})
        return web.json_response({"Result": "OK"})

    # ------------------------------------------------------- fake Cloudflare
    async def cf_zones(self, request: web.Request) -> web.Response:
        if request.headers.get("Authorization") != "Bearer cf-test-token":
            return web.json_response({"success": False, "errors": [{"message": "Invalid token"}]}, status=403)
        name = request.query.get("name", "")
        result = [{"id": "zone1", "name": name, "status": "active", "plan": {"name": "Free"}}] \
            if name == "example.test" else []
        return web.json_response({"success": True, "result": result})

    async def cf_setting(self, request: web.Request) -> web.Response:
        values = {"security_level": "low", "always_use_https": "off", "ssl": "flexible",
                  "min_tls_version": "1.0", "browser_check": "on", "challenge_ttl": 1800, "waf": "off"}
        setting = request.match_info["setting"]
        return web.json_response({"success": True, "result": {"id": setting, "value": values.get(setting)}})

    async def cf_rulesets(self, request: web.Request) -> web.Response:
        return web.json_response({"success": True, "result": [
            {"name": "default", "phase": "http_request_sanitize", "kind": "managed"}]})


if __name__ == "__main__":
    import sys

    server = LocalTestServer(port=int(sys.argv[1]) if len(sys.argv) > 1 else 8765).start()
    print(f"Local test server running at {server.url} (Ctrl+C to stop)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()
