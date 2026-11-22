"""Test History: search, filter, inspect, compare, export and delete past runs."""

from __future__ import annotations

from typing import Any

from PySide6.QtWidgets import QAbstractItemView, QComboBox, QDialog, QLineEdit, QVBoxLayout, QWidget

from ...core.i18n import NOT_AVAILABLE, PERFORMANCE_TYPES, STATUS_LABELS, TEST_TYPE_LABELS, TEST_TYPE_SHORT
from ...core.models import RunRecord, RunStatus, TestType
from ...reporting.html_report import fmt, local_time, pct
from ..components.exporting import export_with_dialog
from ..components.widgets import Banner, Card, button, confirm, fill_table, label, make_table, row
from .base import AppContext

STATUS_COLORS = {"completed": "#4ade80", "stopped": "#94a3b8", "auto_stopped": "#fbbf24",
                 "failed": "#f87171", "running": "#7dd3fc"}
# (label, summary key, unit, True when a lower value is better)
COMPARE_ROWS: list[tuple[str, str, str, bool | None]] = [
    ("إجمالي الطلبات", "total", "", None), ("متوسط RPS", "rps", "", False), ("أقصى RPS", "peak_rps", "", False),
    ("أقصى مستخدمين", "peak_users", "", None), ("متوسط الاستجابة", "avg_ms", "ms", True),
    ("p50", "p50_ms", "ms", True), ("p90", "p90_ms", "ms", True), ("p95", "p95_ms", "ms", True),
    ("p99", "p99_ms", "ms", True), ("نسبة الأخطاء", "error_rate", "%", True), ("فاشلة", "failed", "", True),
    ("HTTP 5xx", "s5xx", "", True), ("HTTP 429", "s429", "", None),
    ("أعلى تزامن مستدام مُختبَر", "max_sustainable_tested_users", "", False),
]


def compare_rows(a: RunRecord, b: RunRecord) -> tuple[list[list[str]], list[str]]:
    """Rows (metric, A, B, change) and a colour per row for the change column."""
    rows, colors = [], []
    for title, key, unit, lower_is_better in COMPARE_ROWS:
        va, vb = a.summary.get(key), b.summary.get(key)
        show = (lambda v: pct(v)) if unit == "%" else (lambda v: fmt(v, unit))
        change, color = "—", ""
        if isinstance(va, (int, float)) and isinstance(vb, (int, float)):
            delta = vb - va
            if unit == "%":
                change = f"{delta * 100:+.1f} نقطة"
            elif va:
                change = f"{delta:+,.2f} ({delta / va * 100:+.0f}%)"
            else:
                change = f"{delta:+,.2f}"
            if delta and lower_is_better is not None:
                better = (delta < 0) == lower_is_better
                color = "#4ade80" if better else "#f87171"
        rows.append([title, show(va), show(vb), change])
        colors.append(color)
    return rows, colors


class CompareDialog(QDialog):
    def __init__(self, a: RunRecord, b: RunRecord, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("مقارنة تشغيلين")
        self.resize(820, 620)
        layout = QVBoxLayout(self)
        if a.test_type != b.test_type or a.target_url != b.target_url:
            layout.addWidget(Banner("التشغيلان يختلفان في النوع أو الهدف؛ المقارنة للاستئناس فقط.", "warn"))
        layout.addWidget(label(
            f"(أ) #{a.id} {a.name} — {local_time(a.started_at)}\n(ب) #{b.id} {b.name} — {local_time(b.started_at)}",
            "Muted"))
        self.table = make_table(["المقياس", f"(أ) #{a.id}", f"(ب) #{b.id}", "التغيّر من أ إلى ب"], 0)
        rows, colors = compare_rows(a, b)
        fill_table(self.table, rows, {3: colors})
        layout.addWidget(self.table, 1)
        layout.addWidget(label("الأخضر = تحسّن، الأحمر = تراجع. القيم «غير متاح» لم تُقَس في ذلك التشغيل.", "Hint"))
        close = button("إغلاق")
        close.clicked.connect(self.accept)
        layout.addLayout(row(1, close))


class HistoryPage(QWidget):
    def __init__(self, app: AppContext) -> None:
        super().__init__()
        self.setObjectName("Page")
        self.app = app
        self.runs: list[RunRecord] = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        self.search = QLineEdit()
        self.search.setPlaceholderText("ابحث باسم الاختبار أو عنوان الموقع…")
        self.search.setClearButtonEnabled(True)
        self.type_filter = QComboBox()
        self.type_filter.addItem("كل الأنواع", "")
        for test_type in TestType:
            self.type_filter.addItem(TEST_TYPE_LABELS[test_type.value], test_type.value)
        self.status_filter = QComboBox()
        self.status_filter.addItem("كل الحالات", "")
        for status in RunStatus:
            self.status_filter.addItem(STATUS_LABELS[status.value], status.value)
        self.search.textChanged.connect(self.refresh)
        self.type_filter.currentIndexChanged.connect(self.refresh)
        self.status_filter.currentIndexChanged.connect(self.refresh)
        filters = row(self.search, self.type_filter, self.status_filter)
        filters.setStretch(0, 1)
        layout.addLayout(filters)

        self.table = make_table(
            ["#", "الاسم", "النوع", "الهدف", "الحالة", "التاريخ", "الطلبات", "p95", "نسبة الأخطاء"], 1)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.itemSelectionChanged.connect(self._update_actions)
        self.table.itemDoubleClicked.connect(lambda _: self.open_report())
        layout.addWidget(self.table, 1)
        self.count_label = label("", "Hint")
        layout.addWidget(self.count_label)

        self.view_button = button("عرض التقرير", "Primary")
        self.compare_button = button("مقارنة تشغيلين", "", "حدّد تشغيلين بالضغط مع Ctrl")
        self.export_buttons = {f: button(f"تصدير {f.upper()}") for f in ("pdf", "html", "json", "csv")}
        self.delete_button = button("حذف")
        self.view_button.clicked.connect(self.open_report)
        self.compare_button.clicked.connect(self.compare)
        self.delete_button.clicked.connect(self.delete_selected)
        for fmt_name, export_button in self.export_buttons.items():
            export_button.clicked.connect(lambda _=False, f=fmt_name: self.export(f))
        layout.addLayout(row(self.view_button, self.compare_button, *self.export_buttons.values(), 1,
                             self.delete_button))
        self.banner = Banner()
        layout.addWidget(self.banner)

        app.controller.data_changed.connect(self.refresh)
        self.refresh()

    def refresh(self) -> None:
        self.runs = self.app.container.repo.list_runs(
            search=self.search.text(), test_type=self.type_filter.currentData() or "",
            status=self.status_filter.currentData() or "")
        rows: list[list[Any]] = []
        for run in self.runs:
            s = run.summary
            rows.append([run.id, run.name, TEST_TYPE_SHORT.get(run.test_type.value, ""), run.target_url,
                         STATUS_LABELS.get(run.status.value, ""), local_time(run.started_at),
                         fmt(s.get("total")) if s else NOT_AVAILABLE, fmt(s.get("p95_ms"), "ms"),
                         pct(s.get("error_rate")) if run.test_type.value in PERFORMANCE_TYPES else "—"])
        fill_table(self.table, rows, {4: [STATUS_COLORS.get(r.status.value, "") for r in self.runs]})
        total = self.app.container.repo.counts()["runs"]
        self.count_label.setText(f"يُعرض {len(self.runs)} من {total} تشغيل محفوظ.")
        self._update_actions()

    def selected_runs(self) -> list[RunRecord]:
        rows = sorted({index.row() for index in self.table.selectionModel().selectedRows()})
        return [self.runs[r] for r in rows if r < len(self.runs)]

    def _update_actions(self) -> None:
        count = len(self.selected_runs())
        self.view_button.setEnabled(count == 1)
        self.compare_button.setEnabled(count == 2)
        self.delete_button.setEnabled(count >= 1)
        for export_button in self.export_buttons.values():
            export_button.setEnabled(count == 1)

    def open_report(self) -> None:
        runs = self.selected_runs()
        if len(runs) == 1:
            self.app.navigate("reports", run_id=runs[0].id)

    def compare(self) -> None:
        runs = self.selected_runs()
        if len(runs) == 2:
            older, newer = sorted(runs, key=lambda r: (r.started_at, r.id or 0))
            CompareDialog(older, newer, self).exec()

    def export(self, fmt_name: str) -> None:
        runs = self.selected_runs()
        if len(runs) != 1:
            return
        try:
            path = export_with_dialog(self, self.app.container, runs[0], fmt_name)
        except OSError as exc:
            self.banner.show_message(f"تعذّر حفظ الملف: {exc}", "error")
            return
        if path:
            self.banner.show_message(f"تم حفظ التقرير: {path}", "ok")

    def delete_selected(self, *, ask: bool = True) -> None:
        runs = self.selected_runs()
        if not runs:
            return
        names = "، ".join(f"#{r.id}" for r in runs)
        if ask and not confirm(self, "حذف من السجل", f"حذف التشغيل {names} نهائياً من السجل؟", "حذف"):
            return
        active = self.app.controller.current
        for run in runs:
            if active is not None and active.record.id == run.id:
                self.banner.show_message("لا يمكن حذف تشغيل ما زال قيد التنفيذ.", "warn")
                continue
            self.app.container.repo.delete_run(run.id)
            self.app.container.audit.record("run_deleted", target=run.target_url, run_id=run.id)
        self.app.controller.data_changed.emit()


__all__ = ["HistoryPage", "CompareDialog", "compare_rows", "Card"]
