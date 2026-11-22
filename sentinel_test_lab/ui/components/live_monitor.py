"""Live monitoring dashboard: real metrics polled from the running test once a second."""

from __future__ import annotations

from typing import Any

import pyqtgraph as pg
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QPlainTextEdit, QProgressBar, QTabWidget, QVBoxLayout, QWidget

from ...core.i18n import NOT_AVAILABLE, STATUS_LABELS
from ...core.models import RunRecord
from ...core.test_orchestrator import PreparedRun
from .widgets import STATUS_TONES, Badge, Banner, Card, FindingsTable, StatCard, button, label, row

pg.setConfigOptions(antialias=True, background="#131920", foreground="#8b98a8")

BLUE, CYAN, AMBER, RED, GREY = "#3b82f6", "#22b8cf", "#f59e0b", "#ef4444", "#64748b"


class LiveChart(pg.PlotWidget):
    """A compact time-series chart with named curves."""

    def __init__(self, title: str, curves: list[tuple[str, str, bool]], unit: str = "") -> None:
        super().__init__()
        self.setMinimumHeight(170)
        self.setMenuEnabled(False)
        self.setMouseEnabled(x=False, y=False)
        self.hideButtons()
        self.setTitle(title, color="#b6c2cf", size="10pt")
        self.showGrid(x=False, y=True, alpha=0.15)
        self.setLabel("bottom", "s")
        if unit:
            self.setLabel("left", unit)
        self.setLayoutDirection(Qt.LayoutDirection.LeftToRight)  # time always runs left to right
        self.getViewBox().setLimits(yMin=0, xMin=0, minYRange=1)
        legend = self.addLegend(offset=(46, 4), labelTextSize="8pt")
        legend.setBrush(pg.mkBrush("#131920cc"))
        self._curves: dict[str, pg.PlotDataItem] = {}
        for name, color, dashed in curves:
            pen = pg.mkPen(color, width=2, style=Qt.PenStyle.DashLine if dashed else Qt.PenStyle.SolidLine)
            self._curves[name] = self.plot([], [], pen=pen, name=name)

    def set_data(self, name: str, xs: list[float], ys: list[float]) -> None:
        self._curves[name].setData(xs, ys)

    def clear_data(self) -> None:
        for curve in self._curves.values():
            curve.setData([], [])

    def point_count(self, name: str) -> int:
        xs, _ = self._curves[name].getData()
        return 0 if xs is None else len(xs)


class LiveMonitor(QWidget):
    """Shows the metrics of one run while it executes and its findings afterwards."""

    stop_requested = Signal()
    report_requested = Signal(int)

    def __init__(self) -> None:
        super().__init__()
        self._prepared: PreparedRun | None = None
        self._record: RunRecord | None = None
        self._log_count = 0
        self._timer = QTimer(self)
        self._timer.setInterval(500)
        self._timer.timeout.connect(self.refresh)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)

        # ---- header: status, progress, emergency stop
        self.status_badge = Badge("جاهز")
        self.status_text = label("اضبط الإعدادات ثم اضغط «بدء الاختبار». ستظهر المقاييس الحقيقية هنا لحظياً.", "Muted", wrap=True)
        self.stop_button = button("⏹  إيقاف طارئ", "Danger", "يوقف الاختبار فوراً ويلغي كل الطلبات الجارية")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self._on_stop_clicked)
        self.report_button = button("عرض التقرير", "Primary")
        self.report_button.setVisible(False)
        self.report_button.clicked.connect(lambda: self._record and self.report_requested.emit(self._record.id))
        header = QHBoxLayout()
        header.addWidget(self.status_badge)
        header.addWidget(self.status_text, 1)
        header.addWidget(self.report_button)
        header.addWidget(self.stop_button)
        root.addLayout(header)
        self.progress = QProgressBar()
        self.progress.setRange(0, 1000)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(8)
        root.addWidget(self.progress)
        self.result_banner = Banner()
        root.addWidget(self.result_banner)

        self.tabs = QTabWidget()
        root.addWidget(self.tabs, 1)
        self.tabs.addTab(self._build_live_tab(), "المراقبة الحية")
        self.findings = FindingsTable()
        self.tabs.addTab(self.findings, "الملاحظات والتوصيات")
        self.log = QPlainTextEdit()
        self.log.setObjectName("Log")
        self.log.setReadOnly(True)
        self.log.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
        self.tabs.addTab(self.log, "سجل الأحداث")

    def _build_live_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(10)
        self.stats: dict[str, StatCard] = {}
        specs = [
            ("rps", "الطلبات/ث (RPS)", "", "عدد الطلبات المكتملة في آخر ثانية"),
            ("total", "إجمالي الطلبات", "", ""), ("success", "ناجحة", "", "ردود 2xx و 3xx"),
            ("failed", "فاشلة", "", "ردود 4xx و 5xx وأخطاء الاتصال"),
            ("s2xx", "HTTP 2xx", "", ""), ("s3xx", "HTTP 3xx", "", "لا تُتابَع إعادة التوجيه"),
            ("s4xx", "HTTP 4xx", "", "تشمل 429"), ("s5xx", "HTTP 5xx", "", ""),
            ("avg_ms", "متوسط الاستجابة", "ms", ""), ("p50_ms", "p50", "ms", "نصف الطلبات أسرع من هذه القيمة"),
            ("p90_ms", "p90", "ms", ""), ("p95_ms", "p95", "ms", "95% من الطلبات أسرع من هذه القيمة"),
            ("p99_ms", "p99", "ms", ""), ("error_rate", "نسبة الأخطاء", "%", ""),
            ("users", "المستخدمون الحاليون", "", "عدد المستخدمين الافتراضيين النشطين الآن"),
            ("elapsed_s", "مدة الاختبار", "ث", ""),
        ]
        grid = QGridLayout()
        grid.setSpacing(8)
        for index, (key, title, unit, tip) in enumerate(specs):
            card = StatCard(title, unit, tip)
            self.stats[key] = card
            grid.addWidget(card, index // 4, index % 4)
        layout.addLayout(grid)

        charts = QHBoxLayout()
        charts.setSpacing(8)
        self.rps_chart = LiveChart("RPS / المستخدمون", [("RPS", BLUE, False), ("Users", GREY, True)])
        self.latency_chart = LiveChart("زمن الاستجابة", [("avg", CYAN, False), ("p95", AMBER, False)], "ms")
        self.error_chart = LiveChart("الأخطاء في الثانية", [("failed", RED, False), ("429", AMBER, True)])
        for chart in (self.rps_chart, self.latency_chart, self.error_chart):
            charts.addWidget(chart, 1)
        layout.addLayout(charts, 1)

        host = Card()
        host.body.setContentsMargins(12, 8, 12, 10)
        self.host_title = label("موارد هذا الجهاز (مولّد الحمل)", "Muted")
        host.add(self.host_title)
        self.host_stats: dict[str, StatCard] = {}
        strip = QHBoxLayout()
        strip.setSpacing(8)
        for key, title, unit in (("cpu_percent", "CPU", "%"), ("ram_percent", "RAM", "%"),
                                 ("disk_percent", "القرص", "%"), ("net_sent_kbps", "الشبكة ↑", "kbps"),
                                 ("net_recv_kbps", "الشبكة ↓", "kbps"), ("c_cpu", "حاوية CPU", "%"),
                                 ("c_mem", "حاوية RAM", "MB"), ("db", "قاعدة البيانات", "")):
            card = StatCard(title, unit)
            card.value_label.setStyleSheet("font-size: 11.5pt;")
            card.setMinimumWidth(96)
            self.host_stats[key] = card
            strip.addWidget(card, 1)
        self.host_stats["db"].setToolTip("لا يوجد تكامل لمراقبة قواعد البيانات في هذا الإصدار")
        for key in ("c_cpu", "c_mem"):
            self.host_stats[key].setToolTip("موارد حاوية Docker الخاصة بالخادم؛ اخترها من الإعدادات")
        host.add(strip)
        layout.addWidget(host)
        return tab

    # ---------------------------------------------------------------- control
    def start(self, prepared: PreparedRun) -> None:
        self._prepared, self._record, self._log_count = prepared, None, 0
        for chart in (self.rps_chart, self.latency_chart, self.error_chart):
            chart.clear_data()
        self.log.clear()
        self.findings.set_findings([])
        self.result_banner.show_message("")
        self.report_button.setVisible(False)
        self.status_badge.set("قيد التشغيل", "info")
        self.status_text.setText(f"{prepared.record.name} — {prepared.target.base_url}")
        self.stop_button.setEnabled(True)
        self.stop_button.setText("⏹  إيقاف طارئ")
        self.progress.setValue(0)
        scope = ("موارد هذا الجهاز (الهدف محلي: تشمل الخادم ومولّد الحمل)" if prepared.target.is_local
                 else "موارد هذا الجهاز (مولّد الحمل فقط — مقاييس الخادم البعيد غير متاحة)")
        self.host_title.setText(scope)
        self.tabs.setCurrentIndex(0)
        self.refresh()
        self._timer.start()

    def finish(self, record: RunRecord) -> None:
        self._timer.stop()
        self.refresh()
        self._record = record
        self._prepared = None
        self.stop_button.setEnabled(False)
        self.stop_button.setText("⏹  إيقاف طارئ")
        status = record.status.value
        self.status_badge.set(STATUS_LABELS[status], STATUS_TONES.get(status, ""))
        tone = {"completed": "ok", "auto_stopped": "warn", "failed": "error"}.get(status, "info")
        message = STATUS_LABELS[status]
        if record.stop_reason:
            message += f" — {record.stop_reason}"
        total = record.summary.get("total")
        if total:
            message += f"  ·  {total:,} طلب"
        self.result_banner.show_message(message, tone)
        self.progress.setValue(1000 if status == "completed" else self.progress.value())
        self.findings.set_findings(record.findings)
        self.tabs.setTabText(1, f"الملاحظات والتوصيات ({len(record.findings)})")
        self.report_button.setVisible(record.id is not None)
        if record.findings and record.test_type.value in ("security", "ddos_posture", "brute_force", "flood"):
            self.tabs.setCurrentIndex(1)

    @property
    def active(self) -> bool:
        return self._prepared is not None

    def _on_stop_clicked(self) -> None:
        self.stop_button.setEnabled(False)
        self.stop_button.setText("جارٍ الإيقاف…")
        self.stop_requested.emit()

    # ---------------------------------------------------------------- refresh
    def refresh(self) -> None:
        prepared = self._prepared
        if prepared is None:
            return
        snap = prepared.metrics.snapshot()
        values: dict[str, Any] = snap.to_dict()
        has_data = snap.total > 0
        for key, card in self.stats.items():
            value = values.get(key)
            if key == "error_rate":
                tone = "" if not value else ("bad" if value > 0.05 else "warn")
                card.set_value(None if value is None else value * 100, tone)
            elif key in ("failed", "s5xx"):
                card.set_value(value, "bad" if value else "")
            elif key == "s4xx":
                card.set_value(value, "warn" if value else "")
            elif key in ("success", "s2xx"):
                card.set_value(value, "good" if value else "")
            elif key in ("users", "total", "s3xx", "elapsed_s"):
                card.set_value(value)
            else:  # rps and latency values exist only once requests were measured
                card.set_value(value if has_data else None)

        series = list(prepared.metrics.series)
        xs = [s["t"] for s in series]
        self.rps_chart.set_data("RPS", xs, [s["rps"] for s in series])
        self.rps_chart.set_data("Users", xs, [s["users"] for s in series])
        timed = [s for s in series if s.get("avg_ms") is not None]
        self.latency_chart.set_data("avg", [s["t"] for s in timed], [s["avg_ms"] for s in timed])
        self.latency_chart.set_data("p95", [s["t"] for s in timed], [s["p95_ms"] or s["avg_ms"] for s in timed])
        self.error_chart.set_data("failed", xs, [s["failed"] for s in series])
        self.error_chart.set_data("429", xs, [s["s429"] for s in series])

        system = series[-1].get("system") if series else None
        container = next((s["container"] for s in reversed(series[-5:]) if s.get("container")), None)
        for key, card in self.host_stats.items():
            if key in ("c_cpu", "c_mem"):
                value = (container or {}).get("cpu_percent" if key == "c_cpu" else "mem_used_mb")
            else:
                value = None if key == "db" or not system else system.get(key)
            card.set_value(value, digits=0 if key.startswith("net") else 1)

        duration = max(prepared.config.duration_s, 0.1)
        self.progress.setValue(min(1000, int(snap.elapsed_s / duration * 1000)))
        messages = list(prepared.messages)
        for message in messages[self._log_count:]:
            self.log.appendPlainText(message)
        self._log_count = len(messages)
        if prepared.guard.stopped and self.stop_button.isEnabled():
            self.stop_button.setEnabled(False)

    def stat_text(self, key: str) -> str:
        return self.stats[key].text()


__all__ = ["LiveMonitor", "LiveChart", "NOT_AVAILABLE", "row"]
