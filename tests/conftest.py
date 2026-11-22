from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from sentinel_test_lab.core.audit import AuditLogger
from sentinel_test_lab.core.authorization import build_target
from sentinel_test_lab.core.config import AppPaths, Settings
from sentinel_test_lab.core.models import AuthorizedTarget, Environment, RunRecord, TestConfig
from sentinel_test_lab.core.safety_manager import SafetyManager
from sentinel_test_lab.core.secrets_store import MemorySecretStore
from sentinel_test_lab.core.test_orchestrator import TestOrchestrator
from sentinel_test_lab.database.db import Database
from sentinel_test_lab.database.repository import Repository
from tests.support.local_server import LocalTestServer

ALL_METHODS = ["GET", "HEAD", "POST"]


@dataclass
class Env:
    repo: Repository
    safety: SafetyManager
    orchestrator: TestOrchestrator
    paths: AppPaths
    secrets: MemorySecretStore
    audit: AuditLogger

    def add_target(self, url: str, ips: list[str] | None = None, **overrides) -> AuthorizedTarget:
        ips = ips or ["127.0.0.1"]
        params = dict(
            url=url, name=overrides.pop("name", "local"), environment=Environment.LOCALHOST,
            authorization_statement="I own this local test server", confirmed=True,
            resolved_ips=ips, allow_private=True, allowed_methods=ALL_METHODS,
        )
        params.update(overrides)
        return self.repo.save_target(build_target(**params))

    def enable_elevated(self, **values) -> None:
        settings = self.repo.load_settings()
        settings.elevated_enabled = True
        for key, value in values.items():
            setattr(settings, key, value)
        self.repo.save_settings(settings)

    async def run(self, config: TestConfig, target: AuthorizedTarget, *, elevated: bool = False) -> RunRecord:
        prepared = self.orchestrator.prepare(
            config, target.id, confirmed=True,
            elevated_confirmation=target.host if elevated else "",
        )
        return await self.orchestrator.execute(prepared)


@pytest.fixture()
def env(tmp_path: Path) -> Env:
    paths = AppPaths(tmp_path / "data").ensure()
    repo = Repository(Database(paths.db_path))
    audit = AuditLogger(paths.audit_file, repo)
    safety = SafetyManager(repo.load_settings, audit)
    secrets = MemorySecretStore()
    orchestrator = TestOrchestrator(repo, safety, audit, paths, secrets)
    return Env(repo, safety, orchestrator, paths, secrets, audit)


@pytest.fixture(scope="session")
def _server() -> LocalTestServer:
    server = LocalTestServer(verify_token="").start()
    yield server
    server.stop()


@pytest.fixture()
def server(_server: LocalTestServer) -> LocalTestServer:
    _server.reset()
    _server.verify_token = ""
    return _server


@pytest.fixture()
def settings() -> Settings:
    return Settings()
