"""Report export helpers shared by the History and Reports pages."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QFileDialog, QWidget

from ...app.bootstrap import Container
from ...core.models import RunRecord
from ...reporting.export import default_filename, export_run

FILTERS = {"pdf": "PDF (*.pdf)", "html": "HTML (*.html)", "json": "JSON (*.json)", "csv": "CSV (*.csv)"}


def export_with_dialog(parent: QWidget, container: Container, run: RunRecord, fmt: str) -> Path | None:
    """Ask where to save, export, and audit. Returns the written path or None if cancelled."""
    suggested = container.paths.reports_dir / default_filename(run, fmt)
    chosen, _ = QFileDialog.getSaveFileName(parent, "حفظ التقرير", str(suggested), FILTERS[fmt])
    if not chosen:
        return None
    return export_to(container, run, fmt, Path(chosen))


def export_to(container: Container, run: RunRecord, fmt: str, path: Path) -> Path:
    written = export_run(run, fmt, path)
    container.audit.record("report_exported", target=run.target_url, run_id=run.id, format=fmt,
                           file=str(written))
    return written


def open_path(path: Path) -> None:
    QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
