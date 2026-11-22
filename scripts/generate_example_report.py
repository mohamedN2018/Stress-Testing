"""Generate the example reports in ``examples/`` from real runs against the local test server.

Usage:  .venv\\Scripts\\python.exe scripts\\generate_example_report.py
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sentinel_test_lab.core.audit import AuditLogger  # noqa: E402
from sentinel_test_lab.core.authorization import build_target  # noqa: E402
from sentinel_test_lab.core.config import AppPaths, Thresholds  # noqa: E402
from sentinel_test_lab.core.models import Environment, TestConfig, TestType  # noqa: E402
from sentinel_test_lab.core.safety_manager import SafetyManager  # noqa: E402
from sentinel_test_lab.core.secrets_store import MemorySecretStore  # noqa: E402
from sentinel_test_lab.core.test_orchestrator import TestOrchestrator  # noqa: E402
from sentinel_test_lab.database.db import Database  # noqa: E402
from sentinel_test_lab.database.repository import Repository  # noqa: E402
from sentinel_test_lab.reporting.export import FORMATS, export_run  # noqa: E402
from tests.support.local_server import LocalTestServer  # noqa: E402


async def main() -> None:
    out_dir = ROOT / "examples"
    out_dir.mkdir(exist_ok=True)
    server = LocalTestServer().start()
    with tempfile.TemporaryDirectory() as tmp:
        paths = AppPaths(Path(tmp)).ensure()
        repo = Repository(Database(paths.db_path))
        audit = AuditLogger(paths.audit_file, repo)
        orchestrator = TestOrchestrator(repo, SafetyManager(repo.load_settings, audit), audit, paths,
                                        MemorySecretStore())
        settings = repo.load_settings()
        settings.elevated_enabled, settings.elevated_max_rps = True, 200
        repo.save_settings(settings)
        target = repo.save_target(build_target(
            url=server.url, name="Local test server", environment=Environment.LOCALHOST,
            authorization_statement="Local server started by this script on my own machine.",
            confirmed=True, resolved_ips=["127.0.0.1"], allow_private=True,
            allowed_methods=["GET", "HEAD", "POST"]))

        runs = {
            "stress": TestConfig(
                TestType.STRESS, "مثال: اختبار إجهاد على الخادم المحلي", users=1, duration_s=30,
                rate_limit_rps=200, interval_s=0.0, paths=["/degrade"], timeout_s=5,
                thresholds=Thresholds(max_error_rate=0.1, max_p95_ms=5000, min_samples=100_000,
                                      max_consecutive_failures=100_000),
                extra={"start_users": 4, "step_users": 4, "max_users": 24, "step_duration_s": 5}),
            "security": TestConfig(
                TestType.SECURITY, "مثال: تقييم أمني للخادم المحلي", users=1, duration_s=30,
                rate_limit_rps=5, paths=["/"], timeout_s=5),
        }
        for label, config in runs.items():
            server.reset()
            elevated = target.host if SafetyManager.exceeds_defaults(config) else ""
            prepared = orchestrator.prepare(config, target.id, confirmed=True, elevated_confirmation=elevated)
            record = await orchestrator.execute(prepared)
            print(f"{label}: status={record.status.value} requests={record.summary['total']} "
                  f"server_hits={len(server.hits)} findings={len(record.findings)}")
            for fmt in FORMATS:
                path = export_run(record, fmt, out_dir / f"example-{label}-report.{fmt}")
                print(f"  wrote {path.relative_to(ROOT)} ({path.stat().st_size:,} bytes)")
    server.stop()


if __name__ == "__main__":
    asyncio.run(main())
