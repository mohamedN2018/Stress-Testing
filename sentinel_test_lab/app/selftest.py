"""End-to-end self-test used to verify a packaged build.

    SentinelTestLab.exe --selftest-url http://127.0.0.1:8765 --selftest-out result.json

Runs one real, default-limit load test against a **loopback** address through the
normal orchestrator and safety engine, then exports the four report formats.
Anything that is not a loopback address is refused, so this switch cannot be used
to test a target without going through the normal authorization screen.
"""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
from pathlib import Path
from typing import Any


async def _run(url: str, work: Path) -> dict[str, Any]:
    from ..core.authorization import build_target, classify_ips, parse_target_url, resolve_host
    from ..core.config import AppPaths
    from ..core.models import Environment, TestConfig, TestType
    from ..core.secrets_store import MemorySecretStore
    from ..reporting.export import FORMATS, export_run
    from .bootstrap import build_container

    parsed = parse_target_url(url)
    ips = await resolve_host(parsed.host, parsed.port)
    if classify_ips(ips) != "loopback":
        raise PermissionError("the end-to-end self-test only runs against a loopback address")
    container = build_container(AppPaths(work / "data"), MemorySecretStore())
    target = container.repo.save_target(build_target(
        url=url, name="selftest", environment=Environment.LOCALHOST,
        authorization_statement="Loopback self-test of the packaged application.",
        confirmed=True, resolved_ips=ips, allow_private=True))
    config = TestConfig(TestType.LOAD, "packaged self-test", users=3, duration_s=5, rate_limit_rps=5,
                        interval_s=0.0, paths=[parsed.path or "/"], timeout_s=5)
    prepared = container.orchestrator.prepare(config, target.id, confirmed=True)
    record = await container.orchestrator.execute(prepared)
    reports: dict[str, int] = {}
    for fmt in FORMATS:
        path = export_run(record, fmt, work / "reports" / f"selftest.{fmt}")
        reports[fmt] = path.stat().st_size
    summary = record.summary
    return {
        "status": record.status.value, "stop_reason": record.stop_reason,
        "requests": summary.get("total"), "success": summary.get("success"),
        "p95_ms": summary.get("p95_ms"), "rps": summary.get("rps"),
        "series_points": len(record.series), "reports": reports,
        "pdf_header_ok": (work / "reports" / "selftest.pdf").read_bytes().startswith(b"%PDF"),
        "audit_events": [e["event"] for e in container.repo.list_audit()][::-1],
    }


def run_end_to_end(url: str, out_file: Path | None) -> int:
    """Return 0 when a real run completed with requests and all reports were written."""
    result: dict[str, Any]
    with tempfile.TemporaryDirectory(prefix="sentinel-e2e-", ignore_cleanup_errors=True) as tmp:
        try:
            result = asyncio.run(_run(url, Path(tmp)))
            ok = (result["status"] == "completed" and (result["requests"] or 0) > 0
                  and result["success"] == result["requests"] and result["pdf_header_ok"]
                  and all(size > 500 for size in result["reports"].values()))
        except Exception as exc:  # noqa: BLE001 - reported in the result file
            result, ok = {"error": f"{type(exc).__name__}: {exc}"}, False
        result["ok"] = ok
        logging.shutdown()
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if out_file is not None:
        out_file.write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0 if ok else 1
