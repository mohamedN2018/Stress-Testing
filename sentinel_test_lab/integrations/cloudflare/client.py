"""Read-only Cloudflare API client and Cloudflare network detection.

The API token is supplied by the user (stored in the OS credential store) and
only needs read permissions for the zone. Without a token only the public
indicators (IP ranges, response headers) are used.
"""

from __future__ import annotations

import ipaddress
from typing import Any

import httpx

# Published Cloudflare edge ranges (https://www.cloudflare.com/ips/).
CLOUDFLARE_RANGES = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
    "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
    "2a06:98c0::/29", "2c0f:f248::/32",
)]


def is_cloudflare_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in CLOUDFLARE_RANGES if net.version == addr.version)


class CloudflareError(RuntimeError):
    pass


class CloudflareClient:
    def __init__(self, token: str, api_base: str = "https://api.cloudflare.com/client/v4",
                 timeout_s: float = 15.0) -> None:
        self._api_base = api_base.rstrip("/")
        self._headers = {"Authorization": f"Bearer {token}"}
        self._timeout_s = timeout_s

    async def _get(self, client: httpx.AsyncClient, path: str, **params: Any) -> Any:
        try:
            response = await client.get(f"{self._api_base}{path}", params=params)
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise CloudflareError(f"Cloudflare API: {exc}") from exc
        if response.status_code >= 400 or not payload.get("success", False):
            errors = "; ".join(str(e.get("message", e)) for e in payload.get("errors", [])) or response.status_code
            raise CloudflareError(f"Cloudflare API {path}: {errors}")
        return payload.get("result")

    async def zone_posture(self, domain: str) -> dict[str, Any]:
        """Read the protection-related settings of the zone that owns ``domain``."""
        posture: dict[str, Any] = {"zone": None, "settings": {}, "rulesets": [], "errors": []}
        async with httpx.AsyncClient(timeout=self._timeout_s, headers=self._headers, trust_env=False) as client:
            zone = None
            labels = domain.split(".")
            for i in range(len(labels) - 1):
                candidates = await self._get(client, "/zones", name=".".join(labels[i:]))
                if candidates:
                    zone = candidates[0]
                    break
            if zone is None:
                raise CloudflareError(f"لا توجد Zone للنطاق {domain} ضمن صلاحيات هذا الـ token.")
            zone_id = zone["id"]
            posture["zone"] = {"name": zone.get("name"), "status": zone.get("status"),
                               "plan": (zone.get("plan") or {}).get("name")}
            for setting in ("security_level", "always_use_https", "min_tls_version", "ssl",
                            "browser_check", "challenge_ttl", "waf"):
                try:
                    result = await self._get(client, f"/zones/{zone_id}/settings/{setting}")
                    posture["settings"][setting] = result.get("value") if isinstance(result, dict) else result
                except CloudflareError as exc:
                    posture["errors"].append(str(exc))
            try:
                rulesets = await self._get(client, f"/zones/{zone_id}/rulesets") or []
                posture["rulesets"] = [
                    {"name": r.get("name"), "phase": r.get("phase"), "kind": r.get("kind")} for r in rulesets
                ]
            except CloudflareError as exc:
                posture["errors"].append(str(exc))
        return posture
