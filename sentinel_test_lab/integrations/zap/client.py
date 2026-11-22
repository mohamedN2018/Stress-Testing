"""OWASP ZAP integration through the ZAP daemon's JSON API.

Sentinel Test Lab does not bundle ZAP. The user points the application at a
running ZAP daemon (URL + API key). When none is configured or reachable the
integration reports itself as unavailable and nothing is simulated.

Passive mode only proxies the in-scope URLs through ZAP and reads the passive
scanner's alerts. Active scanning is a separate, explicitly confirmed feature
limited to the in-scope URLs (no recursion) with a hard time limit.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Callable

import httpx

from ...core.models import Finding, Severity

RISK_TO_SEVERITY = {
    "informational": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH,
}


class ZapError(RuntimeError):
    pass


class ZapClient:
    def __init__(self, base_url: str, api_key: str = "", timeout_s: float = 15.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._headers = {"X-ZAP-API-Key": api_key} if api_key else {}
        self._timeout_s = timeout_s

    async def _call(self, client: httpx.AsyncClient, path: str, **params: Any) -> dict[str, Any]:
        try:
            response = await client.get(f"{self._base_url}/JSON/{path}/", params=params)
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ZapError(f"ZAP API ({path}): {exc}") from exc

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=self._timeout_s, headers=self._headers, trust_env=False)

    async def version(self) -> str | None:
        """ZAP version, or None when the daemon is not reachable."""
        try:
            async with self._client() as client:
                return str((await self._call(client, "core/view/version")).get("version", "")) or None
        except ZapError:
            return None

    async def passive_scan(
        self,
        urls: list[str],
        base_url: str,
        should_stop: Callable[[], bool],
        wait_timeout_s: float = 60.0,
    ) -> list[Finding]:
        async with self._client() as client:
            for url in urls:
                if should_stop():
                    return []
                await self._call(client, "core/action/accessUrl", url=url, followRedirects="false")
            deadline = time.monotonic() + wait_timeout_s
            while time.monotonic() < deadline and not should_stop():
                pending = await self._call(client, "pscan/view/recordsToScan")
                if int(pending.get("recordsToScan", 0)) == 0:
                    break
                await asyncio.sleep(0.5)
            return await self._alerts(client, base_url)

    async def active_scan(
        self,
        urls: list[str],
        base_url: str,
        should_stop: Callable[[], bool],
        max_duration_s: float,
        delay_ms: int = 200,
    ) -> list[Finding]:
        """Explicitly authorized active scan of the given URLs only (no recursion)."""
        async with self._client() as client:
            await self._call(client, "ascan/action/setOptionThreadPerHost", Integer=1)
            await self._call(client, "ascan/action/setOptionDelayInMs", Integer=delay_ms)
            deadline = time.monotonic() + max_duration_s
            for url in urls:
                if should_stop() or time.monotonic() >= deadline:
                    break
                await self._call(client, "core/action/accessUrl", url=url, followRedirects="false")
                started = await self._call(client, "ascan/action/scan", url=url, recurse="false")
                scan_id = str(started.get("scan", ""))
                try:
                    while True:
                        status = await self._call(client, "ascan/view/status", scanId=scan_id)
                        if int(status.get("status", 100)) >= 100:
                            break
                        if should_stop() or time.monotonic() >= deadline:
                            await self._call(client, "ascan/action/stop", scanId=scan_id)
                            break
                        await asyncio.sleep(1.0)
                except asyncio.CancelledError:
                    await self._call(client, "ascan/action/stop", scanId=scan_id)
                    raise
            return await self._alerts(client, base_url)

    async def _alerts(self, client: httpx.AsyncClient, base_url: str) -> list[Finding]:
        data = await self._call(client, "core/view/alerts", baseurl=base_url, start=0, count=300)
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for alert in data.get("alerts", []):
            key = (str(alert.get("alert", "")), str(alert.get("url", "")))
            if key in seen:
                continue
            seen.add(key)
            risk = str(alert.get("risk", "informational")).lower()
            findings.append(Finding(
                severity=RISK_TO_SEVERITY.get(risk, Severity.INFO),
                category="zap",
                title=f"ZAP: {alert.get('alert', '')}",
                detail=str(alert.get("description", ""))[:600],
                recommendation=str(alert.get("solution", ""))[:600],
                evidence=f"{alert.get('url', '')} {alert.get('evidence', '')}".strip()[:300],
            ))
        return findings
