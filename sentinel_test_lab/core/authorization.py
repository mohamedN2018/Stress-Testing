"""Authorized-scope rules: URL parsing, network classification, ownership proof.

A target is only ever tested when it has been stored as an
:class:`AuthorizedTarget` and its current DNS resolution still matches the
network class it had when the user authorized it.
"""

from __future__ import annotations

import asyncio
import ipaddress
import posixpath
import secrets
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from .. import USER_AGENT
from .models import AuthorizedTarget, Environment

ALLOWED_METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


class TargetError(ValueError):
    """The URL or target definition is invalid."""


class ScopeError(PermissionError):
    """The request falls outside the authorized scope."""


@dataclass(frozen=True)
class ParsedTarget:
    scheme: str
    host: str
    port: int
    path: str

    @property
    def base_url(self) -> str:
        default = 443 if self.scheme == "https" else 80
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}" + ("" if self.port == default else f":{self.port}")


def parse_target_url(url: str) -> ParsedTarget:
    url = (url or "").strip()
    if not url:
        raise TargetError("عنوان الموقع مطلوب.")
    if "://" not in url:
        url = "https://" + url
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise TargetError(f"عنوان غير صالح: {exc}") from exc
    if parts.scheme not in ("http", "https"):
        raise TargetError("المخططات المدعومة هي http و https فقط.")
    if parts.username or parts.password:
        raise TargetError("لا يُسمح بوضع بيانات دخول داخل العنوان.")
    host = (parts.hostname or "").strip().lower()
    if not host or any(ch in host for ch in " \t\r\n/\\@"):
        raise TargetError("اسم المضيف (host) غير صالح.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.rstrip(".").split(".")
        if any(not lb or len(lb) > 63 or lb.startswith("-") or lb.endswith("-") for lb in labels):
            raise TargetError("اسم المضيف (host) غير صالح.") from None
        try:
            host.encode("idna")
        except UnicodeError as exc:
            raise TargetError("اسم المضيف (host) غير صالح.") from exc
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    return ParsedTarget(parts.scheme, host, port, parts.path or "/")


def classify_ip(ip: str) -> str:
    """Return ``loopback``, ``private`` or ``public`` for an IP address."""
    addr = ipaddress.ip_address(ip.split("%", 1)[0])
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if addr.is_loopback:
        return "loopback"
    if not addr.is_global:
        return "private"
    return "public"


def classify_ips(ips: list[str]) -> str:
    """Network class of a resolution. Mixed answers are treated as the riskiest reading."""
    classes = {classify_ip(ip) for ip in ips}
    if not classes:
        raise TargetError("تعذّر حل اسم المضيف إلى أي عنوان IP.")
    if len(classes) > 1:
        raise ScopeError(
            "اسم المضيف يُحَل إلى عناوين من شبكات مختلفة (عامة وخاصة معاً)؛ تم الرفض احتياطياً."
        )
    return classes.pop()


async def resolve_host(host: str, port: int) -> list[str]:
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TargetError(f"فشل حل DNS للمضيف {host}: {exc.strerror or exc}") from exc
    seen: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.append(ip)
    return seen


def normalize_path(path: str) -> str:
    path = (path or "/").strip()
    if "://" in path or path.startswith("//") or "\\" in path:
        raise ScopeError(f"المسار غير مسموح: {path}")
    if not path.startswith("/"):
        path = "/" + path
    raw, _, query = path.partition("?")
    if any(seg == ".." for seg in raw.split("/")):
        raise ScopeError(f"المسار غير مسموح: {path}")
    clean = posixpath.normpath(raw)
    if raw.endswith("/") and clean != "/":
        clean += "/"
    return clean + (f"?{query}" if query else "")


def path_allowed(target: AuthorizedTarget, path: str) -> bool:
    try:
        clean = normalize_path(path).partition("?")[0]
    except ScopeError:
        return False
    for allowed in target.allowed_paths:
        prefix = normalize_path(allowed).partition("?")[0]
        if prefix == "/" or clean == prefix or clean.startswith(prefix.rstrip("/") + "/"):
            return True
    return False


def ensure_request_in_scope(target: AuthorizedTarget, method: str, path: str) -> str:
    """Validate one request against the target's scope; return the normalized path."""
    if method.upper() not in target.allowed_methods:
        raise ScopeError(f"الطريقة {method} غير مصرّح بها لهذا الهدف.")
    if not path_allowed(target, path):
        raise ScopeError(f"المسار {path} خارج النطاق المصرّح به لهذا الهدف.")
    return normalize_path(path)


async def recheck_scope(target: AuthorizedTarget) -> list[str]:
    """Re-resolve the host right before a run and compare with the authorized class.

    Protects against DNS changes/rebinding that would silently move a test from
    a public host to an internal address (or the other way round).
    """
    ips = await resolve_host(target.host, target.port)
    current = classify_ips(ips)
    if current != target.network_class:
        raise ScopeError(
            f"تغيّر حل DNS للهدف: كان ({target.network_class}) وأصبح ({current}). "
            "أعد فحص الهدف وتصريحه من صفحة «اختبار جديد»."
        )
    if current != "public" and not target.allow_private:
        raise ScopeError("الهدف يُحَل إلى عنوان خاص/محلي بدون تصريح صريح بذلك.")
    return ips


def build_target(
    *,
    url: str,
    name: str,
    environment: Environment,
    authorization_statement: str,
    confirmed: bool,
    resolved_ips: list[str],
    description: str = "",
    allow_private: bool = False,
    allowed_paths: list[str] | None = None,
    allowed_methods: list[str] | None = None,
    verify_tls: bool = True,
) -> AuthorizedTarget:
    """Create an :class:`AuthorizedTarget` after enforcing the authorization rules."""
    if not confirmed:
        raise ScopeError("يجب تأكيد أنك مالك الموقع أو مصرَّح لك باختباره.")
    if not name.strip():
        raise TargetError("اسم الهدف مطلوب.")
    if len(authorization_statement.strip()) < 10:
        raise ScopeError("اكتب إقرار التصريح (من صرّح لك وما نطاق التصريح) في 10 أحرف على الأقل.")
    parsed = parse_target_url(url)
    network_class = classify_ips(resolved_ips)
    if network_class != "public" and not allow_private:
        raise ScopeError(
            "الهدف يُحَل إلى عنوان خاص/داخلي/محلي. فعّل خيار «نظام داخلي/محلي أملكه» للتصريح به صراحةً."
        )
    if network_class == "public" and environment == Environment.LOCALHOST:
        raise ScopeError("بيئة «محلي» لا تصلح لهدف يُحَل إلى عنوان IP عام.")
    methods = [m.upper() for m in (allowed_methods or ["GET", "HEAD"])]
    bad = [m for m in methods if m not in ALLOWED_METHODS]
    if bad or not methods:
        raise TargetError(f"طرق HTTP غير مدعومة: {', '.join(bad) or '-'}")
    paths = [normalize_path(p) for p in (allowed_paths or ["/"]) if p.strip()] or ["/"]
    return AuthorizedTarget(
        name=name.strip(),
        base_url=parsed.base_url,
        scheme=parsed.scheme,
        host=parsed.host,
        port=parsed.port,
        environment=environment,
        authorization_statement=authorization_statement.strip(),
        description=description.strip(),
        allowed_paths=paths,
        allowed_methods=methods,
        pinned_ips=list(resolved_ips),
        allow_private=allow_private and network_class != "public",
        network_class=network_class,
        verify_token=secrets.token_hex(16),
        verify_tls=verify_tls,
    )


# --------------------------------------------------------------- ownership
def verification_path(token: str) -> str:
    return f"/.well-known/sentinel-verify-{token}.txt"


def verification_txt_value(token: str) -> str:
    return f"sentinel-verify={token}"


async def verify_ownership_http(target: AuthorizedTarget, timeout_s: float = 10.0) -> bool:
    """Ownership proof: the owner publishes a file containing the token."""
    url = target.base_url + verification_path(target.verify_token)
    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=timeout_s,
            verify=target.verify_tls,
            trust_env=False,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            response = await client.get(url)
    except httpx.HTTPError:
        return False
    return response.status_code == 200 and target.verify_token in response.text[:512]


async def verify_ownership_dns(target: AuthorizedTarget, timeout_s: float = 8.0) -> bool:
    """Ownership proof: a DNS TXT record ``sentinel-verify=<token>``."""
    from .dns_lookup import lookup

    expected = verification_txt_value(target.verify_token)
    for name in (f"_sentinel-verify.{target.host}", target.host):
        if any(value.strip() == expected for value in await lookup(name, "TXT", timeout_s)):
            return True
    return False
