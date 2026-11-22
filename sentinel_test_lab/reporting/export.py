"""Export a stored run as PDF, HTML, JSON or CSV."""

from __future__ import annotations

import csv
import io
import json
import re
from pathlib import Path

from .. import APP_NAME, __version__
from ..core.i18n import STATUS_LABELS, TEST_TYPE_LABELS
from ..core.models import RunRecord
from .html_report import config_rows, write_html

FORMATS = ("pdf", "html", "json", "csv")
SERIES_COLUMNS = ("t", "phase", "users", "rps", "requests", "failed", "s2xx", "s3xx", "s4xx", "s5xx",
                  "s429", "avg_ms", "p95_ms", "error_rate")
SYSTEM_COLUMNS = ("cpu_percent", "ram_percent", "ram_used_mb", "disk_percent", "net_sent_kbps", "net_recv_kbps")


def to_json(run: RunRecord) -> str:
    payload = {"generator": f"{APP_NAME} {__version__}", **run.to_dict()}
    return json.dumps(payload, ensure_ascii=False, indent=2)


def to_csv(run: RunRecord) -> str:
    """Summary, findings and the per-second series as CSV sections."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["section", "key", "value"])
    for key, value in (
        ("name", run.name), ("target_url", run.target_url),
        ("test_type", TEST_TYPE_LABELS.get(run.test_type.value, run.test_type.value)),
        ("status", STATUS_LABELS.get(run.status.value, run.status.value)),
        ("stop_reason", run.stop_reason), ("started_at", run.started_at), ("finished_at", run.finished_at or ""),
    ):
        writer.writerow(["run", key, value])
    for label, value in config_rows(run.config):
        writer.writerow(["config", label, value])
    for key, value in run.summary.items():
        if isinstance(value, dict):
            value = json.dumps(value, ensure_ascii=False)
        writer.writerow(["summary", key, "" if value is None else value])
    writer.writerow([])
    writer.writerow(["severity", "category", "title", "detail", "recommendation", "evidence"])
    for f in run.findings:
        writer.writerow([f.severity.value, f.category, f.title, f.detail, f.recommendation, f.evidence])
    writer.writerow([])
    writer.writerow([*SERIES_COLUMNS, *SYSTEM_COLUMNS])
    for sample in run.series:
        system = sample.get("system") or {}
        writer.writerow([_cell(sample.get(c)) for c in SERIES_COLUMNS] + [_cell(system.get(c)) for c in SYSTEM_COLUMNS])
    return buffer.getvalue()


def _cell(value: object) -> object:
    return "" if value is None else value


def default_filename(run: RunRecord, fmt: str) -> str:
    slug = re.sub(r"[^\w\-]+", "-", run.name, flags=re.UNICODE).strip("-")[:40] or "run"
    stamp = re.sub(r"[^0-9]", "", run.started_at)[:14]
    return f"sentinel-{run.id or 0}-{slug}-{stamp}.{fmt}"


def export_run(run: RunRecord, fmt: str, path: Path) -> Path:
    fmt = fmt.lower()
    if fmt not in FORMATS:
        raise ValueError(f"Unsupported export format: {fmt}")
    path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        path.write_text(to_json(run), encoding="utf-8")
    elif fmt == "csv":
        path.write_text(to_csv(run), encoding="utf-8-sig")  # BOM: Excel reads Arabic correctly
    elif fmt == "html":
        write_html(run, path)
    else:
        from .pdf_report import write_pdf  # Qt is only needed for PDF

        write_pdf(run, path)
    return path
