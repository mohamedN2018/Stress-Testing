"""Secrets (API keys/tokens) live in the OS credential store, never in files or code."""

from __future__ import annotations

from typing import Protocol

import structlog

log = structlog.get_logger("secrets")

SERVICE = "SentinelTestLab"
ZAP_API_KEY = "zap_api_key"
CLOUDFLARE_TOKEN = "cloudflare_token"


class SecretStore(Protocol):
    def get(self, name: str) -> str: ...
    def set(self, name: str, value: str) -> bool: ...


class KeyringSecretStore:
    """Windows Credential Manager (via ``keyring``)."""

    def get(self, name: str) -> str:
        try:
            import keyring

            return keyring.get_password(SERVICE, name) or ""
        except Exception as exc:  # noqa: BLE001 - backend specific errors
            log.warning("secret_read_failed", name=name, error=type(exc).__name__)
            return ""

    def set(self, name: str, value: str) -> bool:
        try:
            import keyring

            if value:
                keyring.set_password(SERVICE, name, value)
            else:
                try:
                    keyring.delete_password(SERVICE, name)
                except Exception:  # noqa: BLE001 - deleting a missing secret
                    pass
            return True
        except Exception as exc:  # noqa: BLE001
            log.warning("secret_write_failed", name=name, error=type(exc).__name__)
            return False


class MemorySecretStore:
    """In-memory store for tests."""

    def __init__(self) -> None:
        self._values: dict[str, str] = {}

    def get(self, name: str) -> str:
        return self._values.get(name, "")

    def set(self, name: str, value: str) -> bool:
        if value:
            self._values[name] = value
        else:
            self._values.pop(name, None)
        return True
