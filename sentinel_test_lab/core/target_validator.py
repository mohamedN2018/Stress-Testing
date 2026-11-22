"""Pre-flight inspection of a target: URL, DNS, connectivity, TLS, headers."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any

import httpx

from .. import USER_AGENT
from .authorization import ParsedTarget, ScopeError, TargetError, classify_ips, parse_target_url, resolve_host
from .tls_info import TlsInfo, fetch_tls_info


@dataclass
class TargetInspection:
    url: str
    base_url: str = ""
    scheme: str = ""
    host: str = ""
    port: int = 0
    ips: list[str] = field(default_factory=list)
    network_class: str = ""
    reachable: bool = False
    status_code: int | None = None
    http_version: str = ""
    response_time_ms: float | None = None
    redirect_location: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    tls: TlsInfo | None = None
    alt_scheme_note: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.ips) and self.reachable

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TargetValidator:
    """Runs a handful of read-only checks. Never called on the UI thread."""

    def __init__(self, timeout_s: float = 10.0) -> None:
        self._timeout_s = timeout_s

    async def inspect(self, url: str, verify_tls: bool = True) -> TargetInspection:
        result = TargetInspection(url=url)
        try:
            parsed = parse_target_url(url)
        except TargetError as exc:
            result.errors.append(str(exc))
            return result
        result.base_url, result.scheme = parsed.base_url, parsed.scheme
        result.host, result.port = parsed.host, parsed.port
        try:
            result.ips = await resolve_host(parsed.host, parsed.port)
            result.network_class = classify_ips(result.ips)
        except (TargetError, ScopeError) as exc:
            result.errors.append(str(exc))
            return result

        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=self._timeout_s,
            verify=verify_tls,
            trust_env=False,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            await self._probe(client, parsed, result)
            await self._probe_alt_scheme(client, parsed, result)

        if parsed.scheme == "https":
            result.tls = await fetch_tls_info(parsed.host, parsed.port, self._timeout_s)
            if result.tls.error:
                result.errors.append(f"TLS: {result.tls.error}")
        return result

    async def _probe(self, client: httpx.AsyncClient, parsed: ParsedTarget, result: TargetInspection) -> None:
        started = time.perf_counter()
        try:
            response = await client.get(parsed.base_url + parsed.path)
        except httpx.HTTPError as exc:
            result.errors.append(f"فشل الاتصال: {type(exc).__name__}: {exc}")
            return
        result.response_time_ms = round((time.perf_counter() - started) * 1000, 1)
        result.reachable = True
        result.status_code = response.status_code
        result.http_version = response.http_version
        result.headers = {k: v for k, v in response.headers.items()}
        result.redirect_location = response.headers.get("location", "")

    async def _probe_alt_scheme(
        self, client: httpx.AsyncClient, parsed: ParsedTarget, result: TargetInspection
    ) -> None:
        """Check the sibling scheme on default ports only (one request)."""
        if parsed.scheme == "https" and parsed.port == 443:
            alt = f"http://{parsed.host}/"
        elif parsed.scheme == "http" and parsed.port == 80:
            alt = f"https://{parsed.host}/"
        else:
            return
        try:
            response = await client.get(alt)
        except httpx.HTTPError:
            result.alt_scheme_note = (
                "HTTP غير متاح (المنفذ 80 لا يستجيب)."
                if alt.startswith("http://")
                else "HTTPS غير متاح على المنفذ 443."
            )
            return
        location = response.headers.get("location", "")
        if alt.startswith("http://"):
            if response.status_code in (301, 302, 307, 308) and location.startswith("https://"):
                result.alt_scheme_note = "HTTP يُحوَّل تلقائياً إلى HTTPS."
            else:
                result.alt_scheme_note = f"HTTP يستجيب بالحالة {response.status_code} بدون تحويل إلى HTTPS."
        else:
            result.alt_scheme_note = f"HTTPS متاح أيضاً (الحالة {response.status_code})."
