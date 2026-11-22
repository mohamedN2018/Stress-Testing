"""Settings: safety limits, stop thresholds, integrations, data and the audit log."""

from __future__ import annotations

import json

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QLineEdit,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from ...core.config import ABSOLUTE_LIMITS, DEFAULT_LIMITS, Settings
from ...core.secrets_store import CLOUDFLARE_TOKEN, ZAP_API_KEY
from ...integrations.status import IntegrationStatus, local_status, zap_status
from ...reporting.html_report import local_time
from ..components.exporting import open_path
from ..components.widgets import Banner, Card, button, confirm, fill_table, label, make_table, row, scrollable
from ..workers import run_async
from .base import AppContext


def _ltr(edit: QLineEdit) -> QLineEdit:
    edit.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
    edit.setAlignment(Qt.AlignmentFlag.AlignLeft)
    return edit


def _form() -> QFormLayout:
    form = QFormLayout()
    form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
    form.setHorizontalSpacing(14)
    form.setVerticalSpacing(9)
    return form


class SettingsPage(QWidget):
    def __init__(self, app: AppContext) -> None:
        super().__init__()
        self.setObjectName("Page")
        self.app = app
        self._loading = False
        self._zap: IntegrationStatus | None = None
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 0, 6, 0)
        layout.setSpacing(14)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scrollable(content), 1)

        # ------------------------------------------------------- safety
        safety = Card("حدود الأمان")
        safety.add(label(
            f"الحدود الافتراضية (لكل الأهداف): {DEFAULT_LIMITS.max_users} مستخدمين · "
            f"{DEFAULT_LIMITS.max_duration_s} ث · {DEFAULT_LIMITS.max_rps:g} طلب/ث · "
            f"{DEFAULT_LIMITS.max_request_budget} طلب لكل اختبار.\n"
            f"السقف المطلق (لا يمكن تجاوزه بأي إعداد): {ABSOLUTE_LIMITS.max_users} مستخدم · "
            f"{ABSOLUTE_LIMITS.max_duration_s} ث · {ABSOLUTE_LIMITS.max_rps:g} طلب/ث · "
            f"{ABSOLUTE_LIMITS.max_request_budget:,} طلب.", "Hint", wrap=True))
        self.elevated_box = QCheckBox("تفعيل الحدود المرفوعة للأهداف الموثوقة (محلية أو موثّقة الملكية)")
        self.elevated_box.toggled.connect(self._on_elevated_toggled)
        safety.add(self.elevated_box)
        form = _form()
        self.max_users = QSpinBox()
        self.max_users.setRange(DEFAULT_LIMITS.max_users, ABSOLUTE_LIMITS.max_users)
        self.max_duration = QSpinBox()
        self.max_duration.setRange(DEFAULT_LIMITS.max_duration_s, ABSOLUTE_LIMITS.max_duration_s)
        self.max_duration.setSuffix(" ث")
        self.max_rps = QDoubleSpinBox()
        self.max_rps.setRange(DEFAULT_LIMITS.max_rps, ABSOLUTE_LIMITS.max_rps)
        self.max_rps.setDecimals(0)
        self.max_rps.setSuffix(" طلب/ث")
        self.max_budget = QSpinBox()
        self.max_budget.setRange(DEFAULT_LIMITS.max_request_budget, ABSOLUTE_LIMITS.max_request_budget)
        self.max_budget.setSingleStep(1000)
        form.addRow("أقصى مستخدمين", self.max_users)
        form.addRow("أقصى مدة", self.max_duration)
        form.addRow("أقصى معدل", self.max_rps)
        form.addRow("ميزانية الطلبات لكل اختبار", self.max_budget)
        safety.add(form)
        safety.add(label("حتى مع التفعيل: كل تشغيل يتجاوز الافتراضي يطلب كتابة اسم المضيف، "
                         "والأهداف غير الموثّقة تبقى على الحدود الافتراضية.", "Hint", wrap=True))
        layout.addWidget(safety)

        # --------------------------------------------------- thresholds
        thresholds = Card("التوقف التلقائي", "يوقف محرك الأمان الاختبار فور تجاوز أي عتبة.")
        form = _form()
        self.error_rate = QSpinBox()
        self.error_rate.setRange(1, 100)
        self.error_rate.setSuffix(" %")
        self.error_rate.setToolTip("نسبة الطلبات الفاشلة خلال آخر 5 ثوانٍ")
        self.p95 = QSpinBox()
        self.p95.setRange(100, 60000)
        self.p95.setSingleStep(500)
        self.p95.setSuffix(" ms")
        self.consecutive = QSpinBox()
        self.consecutive.setRange(3, 1000)
        self.timeout = QDoubleSpinBox()
        self.timeout.setRange(1, 60)
        self.timeout.setDecimals(0)
        self.timeout.setSuffix(" ث")
        form.addRow("أقصى نسبة أخطاء", self.error_rate)
        form.addRow("أقصى p95", self.p95)
        form.addRow("إخفاقات متتالية", self.consecutive)
        form.addRow("مهلة الطلب الواحد", self.timeout)
        thresholds.add(form)
        layout.addWidget(thresholds)

        # ------------------------------------------------- integrations
        integrations = Card("التكاملات الاختيارية",
                            "المحرك الداخلي يعمل دائماً. هذه الأدوات تُستخدم فقط إن كانت مثبتة ومُعدّة.")
        form = _form()
        self.k6_path = _ltr(QLineEdit())
        self.k6_path.setPlaceholderText("فارغ = البحث في PATH")
        browse_k6 = button("استعراض…")
        browse_k6.clicked.connect(lambda: self._browse(self.k6_path))
        self.locust_path = _ltr(QLineEdit())
        self.locust_path.setPlaceholderText("فارغ = البحث في PATH")
        browse_locust = button("استعراض…")
        browse_locust.clicked.connect(lambda: self._browse(self.locust_path))
        self.zap_url = _ltr(QLineEdit())
        self.zap_url.setPlaceholderText("فارغ = تشغيل ZAP المثبت محلياً تلقائياً")
        self.zap_key = _ltr(QLineEdit())
        self.zap_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.cf_token = _ltr(QLineEdit())
        self.cf_token.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("مسار k6", row(self.k6_path, browse_k6))
        form.addRow("مسار Locust", row(self.locust_path, browse_locust))
        form.addRow("ZAP daemon خارجي (اختياري)", self.zap_url)
        form.addRow("مفتاح ZAP API", self.zap_key)
        form.addRow("Cloudflare API token", self.cf_token)
        integrations.add(form)
        integrations.add(label("المفاتيح تُحفظ في Windows Credential Manager وليس في ملفات التطبيق. "
                               "اترك الحقل فارغاً للإبقاء على القيمة المحفوظة.", "Hint", wrap=True))
        self.integrations_table = make_table(["الأداة", "الحالة", "التفاصيل"], 2)
        self.integrations_table.setMinimumHeight(180)
        integrations.add(self.integrations_table)
        self.zap_check = button("فحص الاتصال بـ ZAP")
        self.zap_check.clicked.connect(self.check_zap)
        integrations.add(row(self.zap_check, 1))
        layout.addWidget(integrations)

        # --------------------------------------------------------- data
        data = Card("البيانات والسجلات")
        data.add(label(f"مجلد البيانات: {app.container.paths.data_dir}", "Hint", selectable=True))
        open_data = button("فتح مجلد البيانات")
        open_data.clicked.connect(lambda: open_path(app.container.paths.data_dir))
        open_logs = button("فتح مجلد السجلات")
        open_logs.clicked.connect(lambda: open_path(app.container.paths.log_dir))
        data.add(row(open_data, open_logs, 1))
        data.add(label("سجل التدقيق (آخر 150 حدثاً)", "Muted"))
        self.audit_table = make_table(["الوقت", "الحدث", "الهدف", "التشغيل", "البيانات"], 4)
        self.audit_table.setMinimumHeight(240)
        data.add(self.audit_table)
        layout.addWidget(data)
        layout.addStretch(1)

        self.banner = Banner()
        outer.addWidget(self.banner)
        self.save_button = button("حفظ الإعدادات", "Primary")
        self.save_button.clicked.connect(self.save)
        outer.addLayout(row(self.save_button, 1))

        app.controller.data_changed.connect(self.refresh_tables)
        self.load()

    # ------------------------------------------------------------------ io
    def load(self) -> None:
        self._loading = True
        settings = self.app.container.settings
        self.elevated_box.setChecked(settings.elevated_enabled)
        self.max_users.setValue(settings.elevated_max_users)
        self.max_duration.setValue(settings.elevated_max_duration_s)
        self.max_rps.setValue(settings.elevated_max_rps)
        self.max_budget.setValue(settings.elevated_max_request_budget)
        self.error_rate.setValue(round(settings.thresholds.max_error_rate * 100))
        self.p95.setValue(int(settings.thresholds.max_p95_ms))
        self.consecutive.setValue(settings.thresholds.max_consecutive_failures)
        self.timeout.setValue(settings.request_timeout_s)
        self.k6_path.setText(settings.k6_path)
        self.locust_path.setText(settings.locust_path)
        self.zap_url.setText(settings.zap_url)
        secrets = self.app.container.secrets
        self.zap_key.setPlaceholderText("محفوظ ●●●●" if secrets.get(ZAP_API_KEY) else "لا يوجد مفتاح محفوظ")
        self.cf_token.setPlaceholderText("محفوظ ●●●●" if secrets.get(CLOUDFLARE_TOKEN) else "لا يوجد token محفوظ")
        self._loading = False
        self._sync_elevated()
        self.refresh_tables()

    def collect(self) -> Settings:
        settings = self.app.container.settings
        settings.elevated_enabled = self.elevated_box.isChecked()
        settings.elevated_max_users = self.max_users.value()
        settings.elevated_max_duration_s = self.max_duration.value()
        settings.elevated_max_rps = self.max_rps.value()
        settings.elevated_max_request_budget = self.max_budget.value()
        settings.thresholds.max_error_rate = self.error_rate.value() / 100
        settings.thresholds.max_p95_ms = float(self.p95.value())
        settings.thresholds.max_consecutive_failures = self.consecutive.value()
        settings.request_timeout_s = self.timeout.value()
        settings.k6_path = self.k6_path.text().strip()
        settings.locust_path = self.locust_path.text().strip()
        settings.zap_url = self.zap_url.text().strip().rstrip("/")
        return settings

    def save(self) -> None:
        container = self.app.container
        if self.app.controller.running:
            self.banner.show_message("لا يمكن تغيير الإعدادات أثناء تشغيل اختبار.", "warn")
            return
        settings = self.collect()
        if settings.zap_url and not settings.zap_url.startswith(("http://", "https://")):
            self.banner.show_message("عنوان ZAP يجب أن يبدأ بـ http:// أو https://", "error")
            return
        before = container.settings
        container.repo.save_settings(settings)
        saved_secrets = True
        if self.zap_key.text():
            saved_secrets &= container.secrets.set(ZAP_API_KEY, self.zap_key.text())
        if self.cf_token.text():
            saved_secrets &= container.secrets.set(CLOUDFLARE_TOKEN, self.cf_token.text())
        self.zap_key.clear()
        self.cf_token.clear()
        container.audit.record(
            "settings_changed", elevated_enabled=settings.elevated_enabled,
            elevated_limits=[settings.elevated_max_users, settings.elevated_max_duration_s,
                             settings.elevated_max_rps, settings.elevated_max_request_budget],
            elevated_was_enabled=before.elevated_enabled)
        self._zap = None
        self.load()
        self.app.controller.data_changed.emit()
        if saved_secrets:
            self.banner.show_message("تم حفظ الإعدادات.", "ok")
        else:
            self.banner.show_message("حُفظت الإعدادات، لكن تعذّر حفظ أحد المفاتيح في مخزن بيانات الاعتماد.", "warn")

    # ------------------------------------------------------------- helpers
    def _on_elevated_toggled(self, checked: bool) -> None:
        if checked and not self._loading:
            if not confirm(self, "تفعيل الحدود المرفوعة",
                           "الحدود المرفوعة تسمح بحمل أعلى من الافتراضي الآمن على الأهداف الموثوقة.\n"
                           "استخدمها فقط على أنظمة تملكها وتتحمل هذا الحمل. هل تريد المتابعة؟", "تفعيل"):
                self.elevated_box.setChecked(False)
                return
        self._sync_elevated()

    def _sync_elevated(self) -> None:
        enabled = self.elevated_box.isChecked()
        for widget in (self.max_users, self.max_duration, self.max_rps, self.max_budget):
            widget.setEnabled(enabled)

    def _browse(self, edit: QLineEdit) -> None:
        chosen, _ = QFileDialog.getOpenFileName(self, "اختر الملف التنفيذي", "", "Executables (*.exe);;All (*)")
        if chosen:
            edit.setText(chosen)

    def refresh_tables(self) -> None:
        container = self.app.container
        statuses = local_status(container.settings, container.secrets)
        if self._zap is not None:
            statuses = [self._zap if s.name == "OWASP ZAP" else s for s in statuses]
        fill_table(self.integrations_table, [[
            s.name, "متاح" if s.available else ("لم يُفحص" if s.available is None else "غير متاح"), s.detail,
        ] for s in statuses], {1: ["#4ade80" if s.available else ("#fbbf24" if s.available is None else "#94a3b8")
                                   for s in statuses]})
        entries = container.repo.list_audit(150)
        fill_table(self.audit_table, [[
            local_time(e["ts"]), e["event"], e["target"], e["run_id"] or "",
            json.dumps(e["data"], ensure_ascii=False)[:220],
        ] for e in entries])

    def check_zap(self) -> None:
        container = self.app.container
        settings = self.collect()
        self.zap_check.setEnabled(False)
        self.zap_check.setText("جارٍ الفحص…")

        def done(status: IntegrationStatus) -> None:
            self._zap = status
            self.zap_check.setEnabled(True)
            self.zap_check.setText("فحص الاتصال بـ ZAP")
            self.refresh_tables()
            self.banner.show_message(f"OWASP ZAP: {status.detail}", "ok" if status.available else "warn")

        run_async(lambda: zap_status(settings, container.secrets), done,
                  lambda message: done(IntegrationStatus("OWASP ZAP", False, message)))
