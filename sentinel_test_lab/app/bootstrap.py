"""Composition root: builds the application's services and wires their dependencies."""

from __future__ import annotations

import atexit
from dataclasses import dataclass

from ..core.audit import AuditLogger
from ..core.config import AppPaths, Settings
from ..core.logging_setup import configure_logging
from ..core.safety_manager import SafetyManager
from ..core.secrets_store import KeyringSecretStore, SecretStore
from ..core.target_validator import TargetValidator
from ..core.test_orchestrator import TestOrchestrator
from ..database.db import Database
from ..database.repository import Repository


@dataclass
class Container:
    paths: AppPaths
    repo: Repository
    audit: AuditLogger
    safety: SafetyManager
    secrets: SecretStore
    orchestrator: TestOrchestrator
    validator: TargetValidator

    @property
    def settings(self) -> Settings:
        return self.repo.load_settings()


def _stop_local_tools() -> None:
    from ..integrations.zap.daemon import local_daemon

    local_daemon().stop()


atexit.register(_stop_local_tools)  # never leave a ZAP daemon running after the application


def build_container(paths: AppPaths | None = None, secrets: SecretStore | None = None) -> Container:
    paths = (paths or AppPaths.default()).ensure()
    configure_logging(paths.log_dir)
    repo = Repository(Database(paths.db_path))
    repo.mark_interrupted_runs()
    audit = AuditLogger(paths.audit_file, repo)
    safety = SafetyManager(repo.load_settings, audit)
    secrets = secrets or KeyringSecretStore()
    orchestrator = TestOrchestrator(repo, safety, audit, paths, secrets)
    validator = TargetValidator(repo.load_settings().request_timeout_s)
    return Container(paths, repo, audit, safety, secrets, orchestrator, validator)
