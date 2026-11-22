"""Shared building blocks for the test pages: app context, form helper, TestPage."""

from __future__ import annotations

import math
from dataclasses import dataclass, replace
from typing import Any, Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from ...app.bootstrap import Container
from ...core.config import ABSOLUTE_LIMITS, DEFAULT_LIMITS
from ...core.models import AuthorizedTarget, RunRecord, TestConfig, TestType
from ...core.test_orchestrator import PreparedRun
from ..components.live_monitor import LiveMonitor
from ..components.widgets import Badge, Banner, Card, button, label, row, scrollable
from ..run_controller import RunController


@dataclass
class AppContext:
    container: Container
    controller: RunController
    navigate: Callable[..., None]  # navigate(page_key, **kwargs)


class Form:
    """Builds labelled inputs with tooltips and reports every change to one callback."""

    def __init__(self, on_change: Callable[[], None]) -> None:
        self.layout = QFormLayout()
        self.layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.layout.setHorizontalSpacing(12)
        self.layout.setVerticalSpacing(9)
        self._on_change = on_change
        self.widgets: dict[str, QWidget] = {}

    def _add(self, key: str, text: str, widget: QWidget, tip: str) -> None:
        caption = label(text, "FieldLabel")
        if tip:
            widget.setToolTip(tip)
            caption.setToolTip(tip)
        self.widgets[key] = widget
        self.layout.addRow(caption, widget)

    def int(self, key: str, text: str, lo: int, hi: int, default: int, tip: str = "", suffix: str = "") -> QSpinBox:
        widget = QSpinBox()
        widget.setRange(lo, hi)
        widget.setValue(default)
        if suffix:
            widget.setSuffix(f" {suffix}")
        widget.valueChanged.connect(lambda _: self._on_change())
        self._add(key, text, widget, tip)
        return widget

    def float(self, key: str, text: str, lo: float, hi: float, default: float, tip: str = "",
              suffix: str = "", step: float = 0.5, decimals: int = 1) -> QDoubleSpinBox:
        widget = QDoubleSpinBox()
        widget.setDecimals(decimals)
        widget.setRange(lo, hi)
        widget.setSingleStep(step)
        widget.setValue(default)
        if suffix:
            widget.setSuffix(f" {suffix}")
        widget.valueChanged.connect(lambda _: self._on_change())
        self._add(key, text, widget, tip)
        return widget

    def choice(self, key: str, text: str, items: list[tuple[str, Any]], tip: str = "") -> QComboBox:
        widget = QComboBox()
        for caption, data in items:
            widget.addItem(caption, data)
        widget.currentIndexChanged.connect(lambda _: self._on_change())
        self._add(key, text, widget, tip)
        return widget

    def text(self, key: str, text: str, default: str = "", tip: str = "", placeholder: str = "",
             ltr: bool = True) -> QLineEdit:
        widget = QLineEdit(default)
        widget.setPlaceholderText(placeholder)
        if ltr:
            widget.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
            widget.setAlignment(Qt.AlignmentFlag.AlignLeft)
        widget.textChanged.connect(lambda _: self._on_change())
        self._add(key, text, widget, tip)
        return widget

    def check(self, key: str, text: str, default: bool = False, tip: str = "") -> QCheckBox:
        widget = QCheckBox(text)
        widget.setChecked(default)
        if tip:
            widget.setToolTip(tip)
        widget.toggled.connect(lambda _: self._on_change())
        self.widgets[key] = widget
        self.layout.addRow(widget)
        return widget

    def note(self, text: str) -> None:
        self.layout.addRow(label(text, "Hint", wrap=True))

    def value(self, key: str) -> Any:
        widget = self.widgets[key]
        if isinstance(widget, (QSpinBox, QDoubleSpinBox)):
            return widget.value()
        if isinstance(widget, QComboBox):
            return widget.currentData()
        if isinstance(widget, QCheckBox):
            return widget.isChecked()
        return widget.text().strip()  # type: ignore[union-attr]


def split_paths(text: str) -> list[str]:
    paths = [p.strip() for p in text.replace("\n", ",").split(",") if p.strip()]
    return [p if p.startswith("/") else "/" + p for p in paths] or ["/"]


class TestPage(QWidget):
    """A test category: target picker + settings form on one side, live monitor on the other."""

    __test__ = False
    test_type: TestType
    intro: str = ""
    start_text = "▶  بدء الاختبار"
    default_name = "اختبار"

    def __init__(self, app: AppContext) -> None:
        super().__init__()
        self.setObjectName("Page")
        self.app = app
        self._my_run: PreparedRun | None = None
        self._building = True

        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(14)

        side = QWidget()
        side_layout = QVBoxLayout(side)
        side_layout.setContentsMargins(0, 0, 6, 0)
        side_layout.setSpacing(12)
        if self.intro:
            side_layout.addWidget(Banner(self.intro, "info"))

        # ---- target
        target_card = Card("1. الهدف المصرّح به")
        self.target_combo = QComboBox()
        self.target_combo.currentIndexChanged.connect(self._on_target_changed)
        target_card.add(self.target_combo)
        self.trust_badge = Badge()
        self.limits_label = label("", "Hint", wrap=True)
        manage = button("إدارة الأهداف", "Link")
        manage.clicked.connect(lambda: self.app.navigate("new_test"))
        target_card.add(row(self.trust_badge, 1, manage))
        target_card.add(self.limits_label)
        side_layout.addWidget(target_card)

        # ---- settings
        settings_card = Card("2. إعدادات الاختبار")
        self.form = Form(self._on_form_changed)
        self.form.text("name", "اسم الاختبار", self.default_name, "يظهر في السجل والتقارير", ltr=False)
        self.build_form(self.form)
        settings_card.add(self.form.layout)
        side_layout.addWidget(settings_card)

        # ---- confirm & start
        start_card = Card("3. التأكيد والتشغيل")
        self.validation = Banner()
        start_card.add(self.validation)
        self.confirm_box = QCheckBox("أؤكد أنني مالك هذا الهدف أو مصرَّح لي كتابياً باختباره")
        self.confirm_box.toggled.connect(lambda _: self._update_state())
        start_card.add(self.confirm_box)
        self.start_button = button(self.start_text, "Primary")
        self.start_button.clicked.connect(self._start)
        start_card.add(self.start_button)
        side_layout.addWidget(start_card)
        side_layout.addStretch(1)

        side_scroll = scrollable(side)
        side_scroll.setFixedWidth(410)
        root.addWidget(side_scroll)

        self.monitor = LiveMonitor()
        self.monitor.stop_requested.connect(self.app.controller.stop)
        self.monitor.report_requested.connect(lambda run_id: self.app.navigate("reports", run_id=run_id))
        root.addWidget(self.monitor, 1)

        controller = self.app.controller
        controller.started.connect(self._on_run_started)
        controller.finished.connect(self._on_run_finished)
        controller.data_changed.connect(self.refresh_targets)
        self._building = False
        self.refresh_targets()

    # ----------------------------------------------------- to be overridden
    def build_form(self, form: Form) -> None:
        raise NotImplementedError

    def build_config(self, target: AuthorizedTarget | None) -> TestConfig:
        raise NotImplementedError

    def on_target_changed(self, target: AuthorizedTarget | None) -> None:
        """Hook: adapt the form to the selected target."""

    def block_reason(self) -> str:
        """Hook: a page-specific reason the run cannot start yet ('' = none)."""
        return ""

    # -------------------------------------------------------------- helpers
    def base_config(self, **values: Any) -> TestConfig:
        settings = self.app.container.settings
        return TestConfig(
            test_type=self.test_type,
            name=self.form.value("name") or self.default_name,
            timeout_s=settings.request_timeout_s,
            thresholds=replace(settings.thresholds),
            **values,
        )

    def add_request_fields(self, form: Form, rps_default: float = 5.0, rps_max: float | None = None) -> None:
        form.text("paths", "المسارات", "/", "مسارات مصرّح بها تفصل بينها فاصلة، مثل: /, /api/health",
                  placeholder="/, /about")
        form.choice("method", "الطريقة", [("GET", "GET")], "الطرق المسموحة تُحدَّد عند تصريح الهدف")
        form.float("rps", "حد المعدل", 0.5, rps_max or ABSOLUTE_LIMITS.max_rps, rps_default,
                   "أقصى عدد طلبات في الثانية من كل المستخدمين مجتمعين. الافتراضي الآمن: 5",
                   "طلب/ث")

    def current_target(self) -> AuthorizedTarget | None:
        target_id = self.target_combo.currentData()
        return self.app.container.repo.get_target(target_id) if target_id is not None else None

    def refresh_targets(self) -> None:
        selected = self.target_combo.currentData()
        self.target_combo.blockSignals(True)
        self.target_combo.clear()
        for target in self.app.container.repo.list_targets():
            self.target_combo.addItem(f"{target.name}  —  {target.base_url}", target.id)
        if self.target_combo.count() == 0:
            self.target_combo.addItem("لا توجد أهداف مصرّح بها بعد", None)
        index = self.target_combo.findData(selected)
        self.target_combo.setCurrentIndex(max(index, 0))
        self.target_combo.blockSignals(False)
        self._on_target_changed()

    def select_target(self, target_id: int | None) -> None:
        index = self.target_combo.findData(target_id)
        if index >= 0:
            self.target_combo.setCurrentIndex(index)

    # ---------------------------------------------------------------- state
    def _on_target_changed(self, *_: Any) -> None:
        target = self.current_target()
        safety = self.app.container.safety
        if target is None:
            self.trust_badge.set("لا يوجد هدف", "warn")
            self.limits_label.setText("أضف هدفاً من صفحة «اختبار جديد» ثم عد إلى هنا.")
        else:
            limits = safety.effective_limits(target)
            if target.is_local:
                self.trust_badge.set("محلي موثوق", "good")
            elif target.ownership_verified:
                self.trust_badge.set("ملكية موثّقة", "good")
            else:
                self.trust_badge.set("ملكية غير موثّقة", "warn")
            text = (f"الحدود المتاحة لهذا الهدف: {limits.max_users} مستخدم · {limits.max_duration_s} ث · "
                    f"{limits.max_rps:g} طلب/ث · {limits.max_request_budget:,} طلب.")
            if limits == DEFAULT_LIMITS:
                text += (" لرفعها: وثّق ملكية الهدف ثم فعّل «الحدود المرفوعة» من الإعدادات."
                         if not target.is_trusted else " لرفعها: فعّل «الحدود المرفوعة» من الإعدادات.")
            self.limits_label.setText(text)
            if "method" in self.form.widgets:
                combo: QComboBox = self.form.widgets["method"]  # type: ignore[assignment]
                current = combo.currentData()
                combo.blockSignals(True)
                combo.clear()
                for method in target.allowed_methods:
                    combo.addItem(method, method)
                combo.setCurrentIndex(max(combo.findData(current), 0))
                combo.blockSignals(False)
        self.on_target_changed(target)
        self._update_state()

    def _on_form_changed(self) -> None:
        if not self._building:
            self._update_state()

    def _update_state(self) -> None:
        """Live validation: explain what will happen, or why the run cannot start."""
        if self._building:
            return
        controller = self.app.controller
        target = self.current_target()
        problem, tone, reason = "", "info", ""
        if target is None:
            problem, tone = "لا يوجد هدف مصرّح به. أضف هدفاً أولاً من صفحة «اختبار جديد».", "warn"
            reason = "اختر هدفاً مصرّحاً به أولاً"
        else:
            try:
                config = self.build_config(target)
                problem = self.app.container.safety.preview(config, target)
            except ValueError as exc:
                problem = str(exc)
            if problem:
                tone, reason = "error", "صحّح الإعدادات المشار إليها أولاً"
            else:
                problem = self.describe(config, target)
                if self.app.container.safety.exceeds_defaults(config):
                    tone = "warn"
                    problem += " تتجاوز الحدود الافتراضية: سيُطلب منك كتابة اسم المضيف للتأكيد."
        if not reason:
            reason = self.block_reason()
        if not reason and not self.confirm_box.isChecked():
            reason = "ضع علامة على تأكيد التصريح أولاً"
        if not reason and controller.running:
            reason = "يوجد اختبار آخر قيد التشغيل"
        self.validation.show_message(problem, tone)
        self.start_button.setEnabled(not reason)
        self.start_button.setToolTip(reason or "ابدأ الاختبار بالإعدادات الحالية")
        editable = not (controller.running and self._my_run is not None)
        for widget in self.form.widgets.values():
            widget.setEnabled(editable and self._field_enabled(widget))
        self.target_combo.setEnabled(editable)
        self.confirm_box.setEnabled(editable)

    def _field_enabled(self, widget: QWidget) -> bool:
        return not bool(widget.property("locked"))

    def describe(self, config: TestConfig, target: AuthorizedTarget) -> str:
        budget = config.request_budget or min(
            self.app.container.safety.effective_limits(target).max_request_budget,
            math.ceil(config.rate_limit_rps * config.duration_s) + 1)
        return (f"جاهز: بحد أقصى {budget:,} طلب، بمعدل لا يتجاوز {config.rate_limit_rps:g} طلب/ث، "
                f"ولمدة لا تتجاوز {config.duration_s:g} ث.")

    # ------------------------------------------------------------------ run
    def start_now(self) -> bool:
        """Start with the current settings on behalf of a confirmation the user just gave
        on the New Test page. Returns False (and shows why) when the run cannot start."""
        if self.app.controller.running:
            return False
        self.confirm_box.setChecked(True)
        self._update_state()
        if not self.start_button.isEnabled():
            self.confirm_box.setChecked(False)
            return False
        self._start()
        return True

    def _start(self) -> None:
        target = self.current_target()
        if target is None:
            return
        prepared = self.app.controller.start(self.build_config(target), target, self.confirm_box.isChecked())
        if prepared is not None:
            self._my_run = prepared
            self.monitor.start(prepared)
            self._update_state()

    def _on_run_started(self, prepared: PreparedRun) -> None:
        if prepared is not self._my_run:
            self._update_state()

    def _on_run_finished(self, record: RunRecord) -> None:
        if self._my_run is not None and self._my_run.record is record:
            self.monitor.finish(record)
            self.confirm_box.setChecked(False)  # every run needs a fresh confirmation
        self._my_run = None
        self._update_state()
