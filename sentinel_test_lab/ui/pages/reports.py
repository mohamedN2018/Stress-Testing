"""Reports: preview a run's report and export it as PDF / HTML / JSON / CSV."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QComboBox, QTextBrowser, QVBoxLayout, QWidget

from ...core.i18n import STATUS_LABELS, TEST_TYPE_LABELS
from ...core.models import RunRecord
from ...reporting.html_report import local_time
from ...reporting.pdf_report import build_document
from ..components.exporting import export_to, export_with_dialog, open_path
from ..components.widgets import Banner, button, label, row
from .base import AppContext


class ReportsPage(QWidget):
    def __init__(self, app: AppContext) -> None:
        super().__init__()
        self.setObjectName("Page")
        self.app = app
        self.run: RunRecord | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        self.run_combo = QComboBox()
        self.run_combo.currentIndexChanged.connect(self._on_selected)
        self.export_buttons = {f: button(f"تصدير {f.upper()}", "Primary" if f == "pdf" else "")
                               for f in ("pdf", "html", "json", "csv")}
        for fmt_name, export_button in self.export_buttons.items():
            export_button.clicked.connect(lambda _=False, f=fmt_name: self.export(f))
        self.folder_button = button("فتح مجلد التقارير")
        self.folder_button.clicked.connect(lambda: open_path(self.app.container.paths.reports_dir))
        top = row(label("التشغيل:", "FieldLabel"), self.run_combo, *self.export_buttons.values(),
                  self.folder_button)
        top.setStretch(1, 1)
        layout.addLayout(top)
        self.banner = Banner()
        layout.addWidget(self.banner)

        self.preview = QTextBrowser()
        self.preview.setOpenExternalLinks(False)
        self.preview.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.preview.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
        self.preview.setStyleSheet("QTextBrowser { background: #ffffff; color: #0f172a; border-radius: 8px; }")
        layout.addWidget(self.preview, 1)
        layout.addWidget(label(
            "المعاينة تطابق ملف PDF. تقرير HTML يحتوي نفس البيانات بتنسيق أغنى ورسوم متجهية.", "Hint"))

        app.controller.data_changed.connect(self.refresh)
        self.refresh()

    def refresh(self) -> None:
        selected = self.run_combo.currentData()
        self.run_combo.blockSignals(True)
        self.run_combo.clear()
        for run in self.app.container.repo.list_runs(limit=300):
            if run.status.value == "running":
                continue
            self.run_combo.addItem(
                f"#{run.id}  {run.name}  ·  {TEST_TYPE_LABELS.get(run.test_type.value, '')}  ·  "
                f"{STATUS_LABELS.get(run.status.value, '')}  ·  {local_time(run.started_at)}", run.id)
        if self.run_combo.count() == 0:
            self.run_combo.addItem("لا توجد تشغيلات محفوظة بعد", None)
        index = self.run_combo.findData(selected)
        self.run_combo.setCurrentIndex(max(index, 0))
        self.run_combo.blockSignals(False)
        self._on_selected()

    def show_run(self, run_id: int) -> None:
        index = self.run_combo.findData(run_id)
        if index < 0:
            self.refresh()
            index = self.run_combo.findData(run_id)
        if index >= 0:
            self.run_combo.setCurrentIndex(index)
            self._on_selected()

    def _on_selected(self) -> None:
        run_id = self.run_combo.currentData()
        self.run = self.app.container.repo.get_run(run_id) if run_id is not None else None
        for export_button in self.export_buttons.values():
            export_button.setEnabled(self.run is not None)
        if self.run is None:
            self.preview.setHtml(
                "<p dir='rtl' style='color:#64748b; font-size:12pt; margin:40px;'>"
                "لا يوجد تقرير لعرضه. نفّذ اختباراً أولاً وسيظهر تقريره هنا.</p>")
            return
        self.preview.setDocument(build_document(self.run))

    def export(self, fmt_name: str, path: Path | None = None) -> Path | None:
        """Export the selected run. ``path`` skips the file dialog (used by tests)."""
        if self.run is None:
            return None
        try:
            if path is None:
                written = export_with_dialog(self, self.app.container, self.run, fmt_name)
            else:
                written = export_to(self.app.container, self.run, fmt_name, path)
        except OSError as exc:
            self.banner.show_message(f"تعذّر حفظ الملف: {exc}", "error")
            return None
        if written:
            self.banner.show_message(f"تم حفظ التقرير: {written}", "ok")
        return written
