"""TLS certificate and protocol inspection (read-only handshake)."""

from __future__ import annotations

import asyncio
import socket
import ssl
import warnings
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.x509.oid import NameOID


@dataclass
class TlsInfo:
    available: bool = False
    trusted: bool | None = None
    trust_error: str = ""
    protocol: str = ""
    cipher: str = ""
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    days_remaining: int | None = None
    san: list[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _name(name: x509.Name) -> str:
    for oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME):
        attrs = name.get_attributes_for_oid(oid)
        if attrs:
            return str(attrs[0].value)
    return name.rfc4514_string()


def _handshake(host: str, port: int, timeout_s: float, verify: bool) -> tuple[bytes, str, str]:
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout_s) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True) or b""
            cipher = tls.cipher()
            return der, tls.version() or "", cipher[0] if cipher else ""


def fetch_tls_info_sync(host: str, port: int, timeout_s: float = 8.0) -> TlsInfo:
    info = TlsInfo()
    try:
        der, protocol, cipher = _handshake(host, port, timeout_s, verify=True)
        info.trusted = True
    except ssl.SSLCertVerificationError as exc:
        info.trusted = False
        info.trust_error = exc.verify_message or str(exc)
        try:
            der, protocol, cipher = _handshake(host, port, timeout_s, verify=False)
        except (OSError, ssl.SSLError) as inner:
            info.error = str(inner)
            return info
    except (OSError, ssl.SSLError) as exc:
        info.error = str(exc)
        return info
    info.available = True
    info.protocol, info.cipher = protocol, cipher
    if der:
        try:
            cert = x509.load_der_x509_certificate(der)
            info.subject = _name(cert.subject)
            info.issuer = _name(cert.issuer)
            info.not_before = cert.not_valid_before_utc.isoformat(timespec="seconds")
            info.not_after = cert.not_valid_after_utc.isoformat(timespec="seconds")
            info.days_remaining = (cert.not_valid_after_utc - datetime.now(timezone.utc)).days
            try:
                ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                info.san = [str(v) for v in ext.value.get_values_for_type(x509.DNSName)][:30]
            except x509.ExtensionNotFound:
                pass
        except ValueError as exc:
            info.error = f"تعذّر تحليل الشهادة: {exc}"
    return info


def probe_protocol_sync(host: str, port: int, version: ssl.TLSVersion, timeout_s: float = 6.0) -> bool | None:
    """True if the server accepts ``version``; None when the probe cannot run locally."""
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.set_ciphers("DEFAULT:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        with warnings.catch_warnings():  # probing deprecated versions is the whole point here
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = version
            context.maximum_version = version
    except (ValueError, ssl.SSLError):
        return None  # local OpenSSL build cannot speak this version
    try:
        with socket.create_connection((host, port), timeout=timeout_s) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True
    except ssl.SSLError as exc:
        text = str(exc).lower()
        if "alert" in text:
            return False  # the server answered and refused this version
        if "no protocols available" in text or "unsupported protocol" in text:
            return None  # refused locally by this OpenSSL build, not by the server
        return False
    except OSError:
        return None


async def fetch_tls_info(host: str, port: int, timeout_s: float = 8.0) -> TlsInfo:
    return await asyncio.to_thread(fetch_tls_info_sync, host, port, timeout_s)


async def probe_protocol(host: str, port: int, version: ssl.TLSVersion) -> bool | None:
    return await asyncio.to_thread(probe_protocol_sync, host, port, version)
