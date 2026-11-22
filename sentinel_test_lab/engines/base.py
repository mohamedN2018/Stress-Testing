"""Engine contract and the execution context handed to every engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Protocol

import httpx

from .. import USER_AGENT
from ..core.config import Settings
from ..core.metrics_collector import MetricsCollector
from ..core.models import AuthorizedTarget, EngineOutcome, TestConfig
from ..core.safety_manager import RunGuard


@dataclass
class EngineContext:
    config: TestConfig
    target: AuthorizedTarget
    guard: RunGuard
    metrics: MetricsCollector
    settings: Settings
    work_dir: Path
    emit: Callable[[str], None] = field(default=lambda message: None)
    secrets: dict[str, str] = field(default_factory=dict)

    def new_client(self, max_connections: int | None = None) -> httpx.AsyncClient:
        """HTTP client bound to the authorized target. Redirects are never followed."""
        connections = max_connections or max(4, self.config.users)
        return httpx.AsyncClient(
            base_url=self.target.base_url,
            follow_redirects=False,
            timeout=httpx.Timeout(self.config.timeout_s),
            limits=httpx.Limits(max_connections=connections, max_keepalive_connections=connections),
            verify=self.target.verify_tls,
            trust_env=False,  # never route through system proxies
            # "_headers" is run-time only: validated by SafetyManager and never persisted.
            headers={**(self.config.extra.get("_headers") or {}), "User-Agent": USER_AGENT},
        )


class Engine(Protocol):
    async def run(self, ctx: EngineContext) -> EngineOutcome: ...
