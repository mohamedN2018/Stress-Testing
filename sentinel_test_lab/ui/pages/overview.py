"""Overview: where things stand and the shortest path to running a test."""

from __future__ import annotations

from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QVBoxLayout, QWidget

from ...core.config import ABSOLUTE_LIMITS, DEFAULT_LIMITS
from ...core.i18n import PERFORMANCE_TYPES, STATUS_LABELS, TEST_TYPE_LABELS, TEST_TYPE_SHORT
from ...integrations.status import local_status
from ...reporting.html_report import fmt, local_time, pct
from ..components.widgets import Card, StatCard, button, fill_table, label, make_table, row, scrollable
from .base import AppContext
from .history import STATUS_COLORS

STEPS = [
    ("1", "أضف موقعك", "افحص العنوان وصرّح به كهدف مع تحديد المسارات المسموحة."),
    ("2", "اختر نوع الاختبار", "حمل، إجهاد، قفزة، أو أحد التقييمات الأمنية الدفاعية."),
    ("3", "راقب وصدّر التقرير", "مقاييس حقيقية لحظية، إيقاف طارئ فوري، وتقرير PDF/HTML."),
]


class OverviewPage(QWidget):
    def __init__(self, app: AppContext) -> None:
        super().__init__()
        self.setObjectName("Page")
        self.app = app
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 0, 6, 0)
        layout.setSpacing(14)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scrollable(content))

        stats = QHBoxLayout()
        stats.setSpacing(10)
        self.stat_targets = StatCard("الأهداف المصرّح بها")
        self.stat_runs = StatCard("الاختبارات المحفوظة")
        self.stat_last = StatCard("آخر اختبار")
        self.stat_limits = StatCard("الحدود الحالية", tooltip="مستخدمون / ثوانٍ / طلب في الثانية")
        self.stat_state = StatCard("حالة المحرك")
        for card in (self.stat_targets, self.stat_runs, self.stat_last, self.stat_limits, self.stat_state):
            stats.addWidget(card, 1)
        layout.addLayout(stats)

        start = Card("ابدأ من هنا")
        steps = QGridLayout()
        steps.setHorizontalSpacing(18)
        for column, (number, title, text) in enumerate(STEPS):
            steps.addWidget(label(f"{number}.  {title}", "CardTitle"), 0, column)
            steps.addWidget(label(text, "Hint", wrap=True), 1, column)
            steps.setColumnStretch(column, 1)
        start.add(steps)
        new_test = button("＋  اختبار جديد", "Primary")
        new_test.clicked.connect(lambda: app.navigate("new_test"))
        history = button("سجل الاختبارات")
        history.clicked.connect(lambda: app.navigate("history"))
        start.add(row(new_test, history, 1))
        layout.addWidget(start)

        lower = QHBoxLayout()
        lower.setSpacing(14)
        recent = Card("آخر الاختبارات", "انقر مرتين على أي صف لفتح تقريره.")
        self.recent_table = make_table(["#", "الاسم", "النوع", "الحالة", "التاريخ", "الطلبات", "p95", "الأخطاء"], 1)
        self.recent_table.setMinimumHeight(230)
        self.recent_table.itemDoubleClicked.connect(self._open_recent)
        recent.add(self.recent_table)
        lower.addWidget(recent, 3)

        side = QVBoxLayout()
        side.setSpacing(14)
        safety = Card("محرك الأمان")
        self.safety_text = label("", "Hint", wrap=True)
        safety.add(self.safety_text)
        settings_link = button("فتح الإعدادات", "Link")
        settings_link.clicked.connect(lambda: app.navigate("settings"))
        safety.add(row(settings_link, 1))
        side.addWidget(safety)
        integrations = Card("التكاملات")
        self.integrations_table = make_table(["الأداة", "الحالة", "التفاصيل"], 2)
        self.integrations_table.setMinimumHeight(170)
        integrations.add(self.integrations_table)
        side.addWidget(integrations, 1)
        lower.addLayout(side, 2)
        layout.addLayout(lower, 1)

        app.controller.data_changed.connect(self.refresh)
        app.controller.started.connect(lambda _: self.refresh())
        self.refresh()

    def refresh(self) -> None:
        container = self.app.container
        counts = container.repo.counts()
        settings = container.settings
        self.stat_targets.set_value(counts["targets"])
        self.stat_runs.set_value(counts["runs"])
        self.runs = container.repo.list_runs(limit=8)
        if self.runs:
            last = self.runs[0]
            tone = {"completed": "good", "failed": "bad", "auto_stopped": "warn"}.get(last.status.value, "")
            self.stat_last.set_value(STATUS_LABELS[last.status.value], tone)
        else:
            self.stat_last.set_value(None)
        limits = settings.elevated_limits() if settings.elevated_enabled else DEFAULT_LIMITS
        self.stat_limits.set_value(f"{limits.max_users} / {limits.max_duration_s} / {limits.max_rps:g}",
                                   "warn" if settings.elevated_enabled else "good")
        running = self.app.controller.running
        self.stat_state.set_value("اختبار قيد التشغيل" if running else "جاهز", "warn" if running else "good")
        fill_table(self.recent_table, [[
            run.id, run.name, TEST_TYPE_SHORT.get(run.test_type.value, ""), STATUS_LABELS[run.status.value],
            local_time(run.started_at), fmt(run.summary.get("total")), fmt(run.summary.get("p95_ms"), "ms"),
            pct(run.summary.get("error_rate")) if run.test_type.value in PERFORMANCE_TYPES else "—",
        ] for run in self.runs], {3: [STATUS_COLORS.get(r.status.value, "") for r in self.runs]})
        elevated = ("مفعّلة للأهداف الموثوقة فقط: "
                    f"{limits.max_users} مستخدم / {limits.max_duration_s} ث / {limits.max_rps:g} طلب/ث."
                    if settings.elevated_enabled else "غير مفعّلة.")
        self.safety_text.setText(
            f"• الحدود الافتراضية: {DEFAULT_LIMITS.max_users} مستخدمين، {DEFAULT_LIMITS.max_duration_s} ثانية، "
            f"{DEFAULT_LIMITS.max_rps:g} طلب/ث.\n"
            f"• الحدود المرفوعة: {elevated}\n"
            f"• السقف المطلق غير القابل للتجاوز: {ABSOLUTE_LIMITS.max_users} مستخدم، "
            f"{ABSOLUTE_LIMITS.max_duration_s} ث، {ABSOLUTE_LIMITS.max_rps:g} طلب/ث.\n"
            "• لا يعمل أي اختبار إلا على هدف مصرّح به، وكل تشغيل يُسجَّل في سجل التدقيق.")
        statuses = local_status(settings, container.secrets)
        fill_table(self.integrations_table, [[
            s.name, "متاح" if s.available else ("لم يُفحص" if s.available is None else "غير متاح"), s.detail,
        ] for s in statuses], {1: ["#4ade80" if s.available else ("#fbbf24" if s.available is None else "#94a3b8")
                                   for s in statuses]})

    def _open_recent(self, item) -> None:  # type: ignore[no-untyped-def]
        row_index = item.row()
        if row_index < len(self.runs):
            self.app.navigate("reports", run_id=self.runs[row_index].id)
