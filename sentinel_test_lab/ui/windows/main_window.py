"""Main window: sidebar navigation, page stack and the global run indicator."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QMainWindow,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from ... import APP_NAME, __version__
from ...app.bootstrap import Container
from ...core.models import RunRecord, TestType
from ...core.test_orchestrator import PreparedRun
from ..components.widgets import button, confirm, label, restyle
from ..pages.base import AppContext
from ..pages.history import HistoryPage
from ..pages.new_test import NewTestPage
from ..pages.overview import OverviewPage
from ..pages.reports import ReportsPage
from ..pages.settings import SettingsPage
from ..pages.test_pages import (
    BruteForceTestPage,
    DdosPostureTestPage,
    FloodTestPage,
    LoadTestPage,
    SecurityTestPage,
    SpikeTestPage,
    StressTestPage,
    TabbedTestsPage,
)
from ..run_controller import RunController
from ..workers import wait_for_workers

# key, sidebar title, page subtitle
NAVIGATION = [
    ("overview", "نظرة عامة", "حالة النظام وآخر الاختبارات"),
    ("new_test", "اختبار جديد", "افحص موقعك وصرّح به ثم اختر نوع الاختبار"),
    ("load", "اختبار الحمل", "قياس الأداء تحت حمل طبيعي ومرتفع"),
    ("stress", "اختبار الإجهاد", "تحديد حدود الأداء تدريجياً دون إسقاط الخادم"),
    ("security", "التقييم الأمني", "تقييمات دفاعية غير اقتحامية"),
    ("history", "سجل الاختبارات", "بحث ومقارنة وتصدير الاختبارات السابقة"),
    ("reports", "التقارير", "معاينة وتصدير التقارير"),
    ("settings", "الإعدادات", "حدود الأمان والتكاملات وسجل التدقيق"),
]


class MainWindow(QMainWindow):
    def __init__(self, container: Container) -> None:
        super().__init__()
        self.container = container
        self.setWindowTitle(APP_NAME)
        self.resize(1440, 900)
        self.setMinimumSize(1180, 720)
        self.setLayoutDirection(Qt.LayoutDirection.RightToLeft)

        self.controller = RunController(container, self)
        self.app_context = AppContext(container, self.controller, self.navigate)

        root = QWidget()
        root.setObjectName("Root")
        self.setCentralWidget(root)
        shell = QHBoxLayout(root)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)
        shell.addWidget(self._build_sidebar())

        main = QVBoxLayout()
        main.setContentsMargins(0, 0, 0, 0)
        main.setSpacing(0)
        main.addWidget(self._build_top_bar())
        self.stack = QStackedWidget()
        holder = QWidget()
        holder_layout = QVBoxLayout(holder)
        holder_layout.setContentsMargins(22, 16, 22, 18)
        holder_layout.addWidget(self.stack)
        main.addWidget(holder, 1)
        shell.addLayout(main, 1)

        self.pages: dict[str, QWidget] = {
            "overview": OverviewPage(self.app_context),
            "new_test": NewTestPage(self.app_context),
            "load": LoadTestPage(self.app_context),
            "stress": TabbedTestsPage(self.app_context, [
                ("Stress — الإجهاد التدريجي", StressTestPage), ("Spike — القفزة المفاجئة", SpikeTestPage),
                ("HTTP Flood — مقاومة الإغراق", FloodTestPage)]),
            "security": TabbedTestsPage(self.app_context, [
                ("الثغرات والإعدادات", SecurityTestPage), ("الجاهزية ضد DDoS", DdosPostureTestPage),
                ("الحماية من Brute Force", BruteForceTestPage)]),
            "history": HistoryPage(self.app_context),
            "reports": ReportsPage(self.app_context),
            "settings": SettingsPage(self.app_context),
        }
        for key, _, _ in NAVIGATION:
            self.stack.addWidget(self.pages[key])

        self.controller.started.connect(self._on_run_started)
        self.controller.finished.connect(self._on_run_finished)
        self.controller.data_changed.connect(self._refresh_safety_pill)
        self._pulse = QTimer(self)
        self._pulse.setInterval(1000)
        self._pulse.timeout.connect(self._update_running_pill)
        self._refresh_safety_pill()
        self.navigate("overview")

    # ---------------------------------------------------------------- chrome
    def _build_sidebar(self) -> QWidget:
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(228)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(14, 20, 14, 16)
        layout.setSpacing(4)
        layout.addWidget(label(APP_NAME, "Brand"))
        layout.addWidget(label("مختبر اختبار المواقع المصرّح بها", "BrandSub"))
        layout.addSpacing(18)
        self.nav_group = QButtonGroup(self)
        self.nav_buttons: dict[str, Any] = {}
        for key, title, _ in NAVIGATION:
            nav = button(title, "Nav")
            nav.setCheckable(True)
            nav.clicked.connect(lambda _=False, k=key: self.navigate(k))
            self.nav_group.addButton(nav)
            self.nav_buttons[key] = nav
            layout.addWidget(nav)
        layout.addStretch(1)
        self.safety_pill = label("", "SafetyPill", wrap=True)
        layout.addWidget(self.safety_pill)
        layout.addWidget(label(f"الإصدار {__version__}", "BrandSub"))
        return sidebar

    def _build_top_bar(self) -> QWidget:
        bar = QFrame()
        bar.setObjectName("TopBar")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(22, 12, 22, 12)
        titles = QVBoxLayout()
        titles.setSpacing(0)
        self.page_title = label("", "PageTitle")
        self.page_subtitle = label("", "PageSubtitle")
        titles.addWidget(self.page_title)
        titles.addWidget(self.page_subtitle)
        layout.addLayout(titles, 1)
        self.running_pill = label("", "RunningPill")
        self.running_pill.setVisible(False)
        self.global_stop = button("⏹  إيقاف طارئ", "Danger", "يوقف الاختبار الجاري فوراً من أي صفحة")
        self.global_stop.setVisible(False)
        self.global_stop.clicked.connect(self.emergency_stop)
        layout.addWidget(self.running_pill)
        layout.addWidget(self.global_stop)
        return bar

    # ------------------------------------------------------------ navigation
    def navigate(self, key: str, **kwargs: Any) -> None:
        """Show a page. Optional: ``test_type``/``target_id``/``autostart`` (test pages), ``run_id`` (reports)."""
        index = next(i for i, (k, _, _) in enumerate(NAVIGATION) if k == key)
        _, title, subtitle = NAVIGATION[index]
        self.stack.setCurrentIndex(index)
        self.nav_buttons[key].setChecked(True)
        self.page_title.setText(title)
        self.page_subtitle.setText(subtitle)
        page = self.pages[key]
        target_id = kwargs.get("target_id")
        test_type: TestType | None = kwargs.get("test_type")
        test_page = None
        if isinstance(page, TabbedTestsPage) and test_type is not None:
            page.show_type(test_type, target_id)
            test_page = page.pages[test_type]
        elif isinstance(page, LoadTestPage) and target_id is not None:
            page.select_target(target_id)
            test_page = page
        if test_page is not None and kwargs.get("autostart"):
            test_page.start_now()
        if isinstance(page, ReportsPage) and kwargs.get("run_id") is not None:
            page.show_run(kwargs["run_id"])
        elif isinstance(page, SettingsPage):
            page.refresh_tables()

    @property
    def current_page_key(self) -> str:
        return NAVIGATION[self.stack.currentIndex()][0]

    # ------------------------------------------------------------- run state
    def emergency_stop(self) -> None:
        self.global_stop.setEnabled(False)
        self.global_stop.setText("جارٍ الإيقاف…")
        self.controller.stop()

    def _on_run_started(self, prepared: PreparedRun) -> None:
        self.global_stop.setEnabled(True)
        self.global_stop.setText("⏹  إيقاف طارئ")
        self.global_stop.setVisible(True)
        self.running_pill.setVisible(True)
        self._update_running_pill()
        self._pulse.start()

    def _on_run_finished(self, record: RunRecord) -> None:
        self._pulse.stop()
        self.global_stop.setVisible(False)
        self.running_pill.setVisible(False)

    def _update_running_pill(self) -> None:
        prepared = self.controller.current
        if prepared is None:
            return
        snap = prepared.metrics.snapshot()
        self.running_pill.setText(
            f"● قيد التشغيل: {prepared.record.name}  ·  {snap.elapsed_s:.0f} ث  ·  {snap.total:,} طلب")

    def _refresh_safety_pill(self) -> None:
        settings = self.container.settings
        if settings.elevated_enabled:
            limits = settings.elevated_limits()
            self.safety_pill.setText(
                f"حدود مرفوعة للأهداف الموثوقة\n{limits.max_users} مستخدم · {limits.max_rps:g} طلب/ث")
        else:
            self.safety_pill.setText("الحدود الآمنة الافتراضية\n5 مستخدمين · 60 ث · 5 طلب/ث")
        restyle(self.safety_pill, elevated="true" if settings.elevated_enabled else "false")

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802 - Qt API
        if self.controller.running:
            if not confirm(self, "اختبار قيد التشغيل", "يوجد اختبار قيد التشغيل. إيقافه وإغلاق التطبيق؟",
                           "إيقاف وإغلاق"):
                event.ignore()
                return
            self.controller.stop()
        wait_for_workers(8000)  # let the run finish cleanly: no orphan tasks or processes
        from ...integrations.zap.daemon import local_daemon

        local_daemon().stop()
        event.accept()
