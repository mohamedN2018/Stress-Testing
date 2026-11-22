"""New Test: inspect a website, authorize it as a target, then pick a test category."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QGridLayout,
    QHBoxLayout,
    QLineEdit,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from ...core.authorization import (
    ALLOWED_METHODS,
    ScopeError,
    TargetError,
    build_target,
    verification_path,
    verification_txt_value,
    verify_ownership_dns,
    verify_ownership_http,
)
from ...core.i18n import ENVIRONMENT_LABELS, NOT_AVAILABLE
from ...core.models import AuthorizedTarget, Environment, TestType
from ...core.target_validator import TargetInspection
from ..components.widgets import (
    Badge,
    Banner,
    Card,
    StatCard,
    button,
    confirm,
    fill_table,
    label,
    make_table,
    row,
    scrollable,
)
from ..workers import run_async
from .base import AppContext

NETWORK_LABELS = {"public": "عام (Internet)", "private": "شبكة خاصة/داخلية", "loopback": "محلي (هذا الجهاز)"}
QUICK_TESTS = [
    ("اختبار حمل", "load", TestType.LOAD), ("اختبار إجهاد", "stress", TestType.STRESS),
    ("اختبار قفزة", "stress", TestType.SPIKE), ("مقاومة Flood", "stress", TestType.FLOOD),
    ("تقييم أمني", "security", TestType.SECURITY), ("جاهزية DDoS", "security", TestType.DDOS_POSTURE),
    ("حماية Brute Force", "security", TestType.BRUTE_FORCE),
]


RELATIONS = [
    ("أنا مالك هذا الموقع", "أنا مالك هذا الموقع وأختبره بنفسي.", False),
    ("أنا مطوّر/مدير الموقع ومفوَّض كتابياً من المالك",
     "أنا مطوّر/مدير هذا الموقع ولدي تفويض كتابي من مالكه باختباره.", False),
    ("خادم محلي أو تجريبي على جهازي أو شبكتي", "خادم محلي/تجريبي أملكه وأشغّله بنفسي على جهازي أو شبكتي.", True),
]
SCOPES = [("كل صفحات الموقع", "/"), ("واجهة الـ API فقط (‎/api)", "/api"), ("صفحات الحساب فقط (‎/accounts)", "/accounts")]
METHOD_SETS = [
    ("قراءة فقط (GET, HEAD) — الأكثر أماناً", ("GET", "HEAD")),
    ("قراءة + إرسال نماذج (GET, HEAD, POST)", ("GET", "HEAD", "POST")),
    ("كل الطرق", ALLOWED_METHODS),
]


class NewTestPage(QWidget):
    """Pick-and-run: choose everything from lists, tick the confirmation, press one button."""

    def __init__(self, app: AppContext) -> None:
        super().__init__()
        self.setObjectName("Page")
        self.app = app
        self.inspection: TargetInspection | None = None
        self._pending_action = ""
        self._targets: list[AuthorizedTarget] = []

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 0, 6, 0)
        layout.setSpacing(14)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scrollable(content))

        # ------------------------------------------------ quick start
        quick = Card("اختبار جديد بضغطة واحدة",
                     "اكتب عنوان موقعك أو اختره من القائمة، اختر من القوائم، ثم اضغط «فحص وتشغيل». "
                     "لا حاجة لكتابة أي شيء آخر.")
        form = QGridLayout()
        form.setHorizontalSpacing(12)
        form.setVerticalSpacing(10)
        self.url_combo = QComboBox()
        self.url_combo.setEditable(True)
        self.url_combo.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.url_combo.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.url_combo.setToolTip("اكتب العنوان مرة واحدة؛ بعد حفظه يظهر في هذه القائمة لاختياره مباشرةً")
        self.url_edit = self.url_combo.lineEdit()
        self.url_edit.setPlaceholderText("https://example.com  أو  http://127.0.0.1:8000")
        self.url_edit.setAlignment(Qt.AlignmentFlag.AlignLeft)
        self.url_edit.textChanged.connect(self._on_url_edited)
        self.url_edit.returnPressed.connect(self.inspect)

        self.relation_combo = QComboBox()
        for text, _, _ in RELATIONS:
            self.relation_combo.addItem(text)
        self.relation_combo.setToolTip("إقرارك بعلاقتك بالموقع يُحفظ مع الهدف وفي سجل التدقيق")
        self.scope_combo = QComboBox()
        for text, path in SCOPES:
            self.scope_combo.addItem(text, path)
        self.scope_combo.setToolTip("الجزء المسموح باختباره من الموقع")
        self.methods_combo = QComboBox()
        for text, _ in METHOD_SETS:
            self.methods_combo.addItem(text)
        self.methods_combo.setToolTip("اختر «قراءة + إرسال نماذج» إن أردت تقييم الحماية من Brute Force")
        self.test_combo = QComboBox()
        for text, page, test_type in QUICK_TESTS:
            self.test_combo.addItem(text, (page, test_type.value))
        self.test_combo.setCurrentIndex(4)  # security assessment: read-only and the safest first test
        self.test_combo.setToolTip("يبدأ بالإعدادات الآمنة الافتراضية؛ يمكنك تعديلها لاحقاً من صفحة الاختبار")
        for i, (text, widget) in enumerate((
            ("عنوان الموقع", self.url_combo), ("علاقتك بالموقع", self.relation_combo),
            ("النطاق المسموح", self.scope_combo), ("الطرق المسموحة", self.methods_combo),
            ("نوع الاختبار", self.test_combo),
        )):
            form.addWidget(label(text, "FieldLabel"), i, 0)
            form.addWidget(widget, i, 1)
        form.setColumnStretch(1, 1)
        quick.add(form)
        self.confirm_box = QCheckBox("أؤكد أنني مالك هذا الموقع أو أحمل تصريحاً كتابياً صريحاً باختباره")
        quick.add(self.confirm_box)
        self.inspect_banner = Banner()
        quick.add(self.inspect_banner)
        self.run_button = button("▶  فحص وتشغيل", "Primary",
                                 "يفحص الهدف، يحفظه كهدف مصرّح به، ثم يبدأ الاختبار المختار بالإعدادات الآمنة")
        self.save_button = button("حفظ الهدف فقط")
        self.inspect_button = button("فحص فقط")
        self.advanced_button = button("خيارات متقدمة ▾", "Link")
        self.run_button.clicked.connect(self.quick_run)
        self.save_button.clicked.connect(lambda: self._proceed("save"))
        self.inspect_button.clicked.connect(self.inspect)
        self.advanced_button.clicked.connect(self._toggle_advanced)
        quick.add(row(self.run_button, self.save_button, self.inspect_button, 1, self.advanced_button))
        layout.addWidget(quick)

        # ------------------------------------------------ advanced (optional)
        self.auth_card = Card("خيارات متقدمة (اختيارية)",
                              "تُملأ تلقائياً من اختياراتك أعلاه. عدّلها فقط إن احتجت نطاقاً أدق.")
        advanced = QGridLayout()
        advanced.setHorizontalSpacing(12)
        advanced.setVerticalSpacing(9)
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("تلقائي: اسم المضيف")
        self.env_combo = QComboBox()
        self.env_combo.addItem("تلقائي حسب نوع الشبكة", "")
        for env in Environment:
            self.env_combo.addItem(ENVIRONMENT_LABELS[env.value], env.value)
        self.description_edit = QLineEdit()
        self.description_edit.setPlaceholderText("اختياري")
        self.paths_edit = QLineEdit("/")
        self.paths_edit.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.paths_edit.setAlignment(Qt.AlignmentFlag.AlignLeft)
        self.paths_edit.setToolTip("بادئات المسارات المسموحة، تفصل بينها فاصلة. مثال: /api, /health")
        self.method_boxes: dict[str, QCheckBox] = {}
        methods = QHBoxLayout()
        for method in ALLOWED_METHODS:
            box = QCheckBox(method)
            box.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
            self.method_boxes[method] = box
            methods.addWidget(box)
        methods.addStretch(1)
        self.statement_edit = QPlainTextEdit()
        self.statement_edit.setFixedHeight(54)
        for i, (text, widget) in enumerate((
            ("اسم الهدف", self.name_edit), ("البيئة", self.env_combo), ("وصف", self.description_edit),
            ("المسارات المسموحة", self.paths_edit),
        )):
            advanced.addWidget(label(text, "FieldLabel"), i, 0)
            advanced.addWidget(widget, i, 1)
        advanced.addWidget(label("الطرق المسموحة", "FieldLabel"), 4, 0)
        advanced.addLayout(methods, 4, 1)
        advanced.addWidget(label("إقرار التصريح", "FieldLabel"), 5, 0, Qt.AlignmentFlag.AlignTop)
        advanced.addWidget(self.statement_edit, 5, 1)
        advanced.setColumnStretch(1, 1)
        self.auth_card.add(advanced)
        self.private_box = QCheckBox("هذا نظام داخلي/محلي أملكه وأصرّح باختباره (يُفعَّل تلقائياً عند اختيار «خادم محلي»)")
        self.tls_box = QCheckBox("تجاهل أخطاء شهادة TLS (لشهادات self-signed في بيئات الاختبار فقط)")
        self.auth_card.add(self.private_box)
        self.auth_card.add(self.tls_box)
        self.auth_banner = Banner()
        self.auth_card.add(self.auth_banner)
        self.auth_card.setVisible(False)
        layout.addWidget(self.auth_card)

        # ------------------------------------------------ inspection result
        self.result_card = Card("نتيجة الفحص")
        self.facts: dict[str, StatCard] = {}
        grid = QGridLayout()
        grid.setSpacing(8)
        for i, (key, title) in enumerate((
            ("ips", "DNS / عناوين IP"), ("network", "نوع الشبكة"), ("status", "حالة HTTP"),
            ("time", "زمن الاستجابة الأولي"), ("http", "البروتوكول"), ("tls", "شهادة SSL"),
            ("expiry", "صلاحية الشهادة"), ("alt", "HTTP / HTTPS"),
        )):
            card = StatCard(title)
            card.value_label.setWordWrap(True)
            card.value_label.setStyleSheet("font-size: 10.5pt;")
            self.facts[key] = card
            grid.addWidget(card, i // 4, i % 4)
        self.result_card.add(grid)
        self.result_card.add(label("ترويسات الاستجابة", "Muted"))
        self.headers_table = make_table(["الترويسة", "القيمة"])
        self.headers_table.setMinimumHeight(170)
        self.headers_table.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.result_card.add(self.headers_table)
        self.result_card.setVisible(False)
        layout.addWidget(self.result_card)

        # ------------------------------------------------ saved targets
        targets_card = Card("الأهداف المصرّح بها", "اختر هدفاً محفوظاً ثم نوع الاختبار للانتقال إلى صفحته.")
        self.targets_table = make_table(["الاسم", "العنوان", "البيئة", "الشبكة", "الملكية", "المسارات", "الطرق"], 1)
        self.targets_table.setMinimumHeight(150)
        self.targets_table.itemSelectionChanged.connect(self._update_target_actions)
        targets_card.add(self.targets_table)
        actions = QHBoxLayout()
        self.quick_buttons = []
        for text, page, test_type in QUICK_TESTS:
            quick_button = button(text)
            quick_button.clicked.connect(lambda _=False, p=page, t=test_type: self._launch(p, t))
            self.quick_buttons.append(quick_button)
            actions.addWidget(quick_button)
        actions.addStretch(1)
        targets_card.add(actions)
        self.verify_button = button("توثيق الملكية…", "", "يرفع قيود الهدف غير الموثّق")
        self.verify_button.clicked.connect(self._open_verify_dialog)
        self.delete_button = button("حذف الهدف")
        self.delete_button.clicked.connect(self._delete_target)
        targets_card.add(row(self.verify_button, self.delete_button, 1))
        layout.addWidget(targets_card)
        layout.addStretch(1)

        self.relation_combo.currentIndexChanged.connect(self._apply_choices)
        self.scope_combo.currentIndexChanged.connect(self._apply_choices)
        self.methods_combo.currentIndexChanged.connect(self._apply_choices)
        self.confirm_box.toggled.connect(self._update_save_state)
        self._apply_choices()
        self.app.controller.data_changed.connect(self.refresh_targets)
        self.refresh_targets()

    # --------------------------------------------------------------- choices
    def _apply_choices(self) -> None:
        """Copy the list choices into the (advanced) authorization fields."""
        _, statement, is_local = RELATIONS[self.relation_combo.currentIndex()]
        self.statement_edit.setPlainText(statement)
        self.private_box.setChecked(is_local)
        self.paths_edit.setText(self.scope_combo.currentData() or "/")
        allowed = METHOD_SETS[self.methods_combo.currentIndex()][1]
        for method, box in self.method_boxes.items():
            box.setChecked(method in allowed)
        self._update_save_state()

    def _toggle_advanced(self) -> None:
        visible = self.auth_card.isHidden()
        self.auth_card.setVisible(visible)
        self.advanced_button.setText("خيارات متقدمة ▴" if visible else "خيارات متقدمة ▾")

    def _update_save_state(self) -> None:
        reason = ""
        if not self.url_edit.text().strip():
            reason = "اكتب عنوان الموقع أو اختره من القائمة"
        elif not self.confirm_box.isChecked():
            reason = "ضع علامة على تأكيد الملكية/التصريح أولاً"
        for action_button in (self.run_button, self.save_button):
            action_button.setEnabled(not reason)
        self.run_button.setToolTip(reason or "يفحص الهدف، يحفظه، ثم يبدأ الاختبار المختار")
        self.save_button.setToolTip(reason)
        self.inspect_button.setEnabled(bool(self.url_edit.text().strip()))

    # --------------------------------------------------------------- inspect
    def _on_url_edited(self) -> None:
        if self.inspection is not None:
            self.inspection = None
            self.result_card.setVisible(False)
            self.inspect_banner.show_message("")
        self._update_save_state()

    def inspect(self) -> None:
        url = self.url_edit.text().strip()
        if not url:
            self.inspect_banner.show_message("اكتب عنوان الموقع أو اختره من القائمة أولاً.", "warn")
            return
        self.inspect_button.setEnabled(False)
        self.run_button.setEnabled(False)
        self.save_button.setEnabled(False)
        self.inspect_banner.show_message("جارٍ حل DNS وفحص الاتصال والشهادة…", "info")
        verify = not self.tls_box.isChecked()
        run_async(lambda: self.app.container.validator.inspect(url, verify), self._on_inspected,
                  lambda message: self._on_inspected(TargetInspection(url=url, errors=[message])))

    def _on_inspected(self, result: TargetInspection) -> None:
        self.inspection = result
        self._update_save_state()
        self.result_card.setVisible(bool(result.ips))
        if result.ips:
            tls = result.tls
            self.facts["ips"].set_value("، ".join(result.ips[:3]))
            self.facts["network"].set_value(NETWORK_LABELS.get(result.network_class, result.network_class),
                                            "warn" if result.network_class != "public" else "")
            self.facts["status"].set_value(result.status_code,
                                           "good" if result.status_code and result.status_code < 400 else "bad")
            self.facts["time"].set_value(None if result.response_time_ms is None else f"{result.response_time_ms:g} ms")
            self.facts["http"].set_value(result.http_version or None)
            if tls is None:
                self.facts["tls"].set_value("لا يوجد (HTTP)", "warn")
                self.facts["expiry"].set_value(None)
            elif not tls.available:
                self.facts["tls"].set_value("فشل المصافحة", "bad")
                self.facts["expiry"].set_value(None)
            else:
                trusted = "موثوقة" if tls.trusted else "غير موثوقة"
                self.facts["tls"].set_value(f"{tls.protocol} · {trusted}\n{tls.issuer}",
                                            "good" if tls.trusted else "bad")
                days = tls.days_remaining
                self.facts["expiry"].set_value(None if days is None else f"{days} يوماً",
                                               "bad" if days is not None and days < 21 else "good")
            self.facts["alt"].set_value(result.alt_scheme_note or None)
            fill_table(self.headers_table, [[k, v] for k, v in result.headers.items()])
        action, self._pending_action = self._pending_action, ""
        if not result.ok:
            self.inspect_banner.show_message("تعذّر فحص الهدف: " + " | ".join(result.errors), "error")
            return
        self.inspect_banner.show_message(f"الهدف متاح: {result.base_url}", "ok")
        if action:
            self._proceed(action)

    # ------------------------------------------------------------- authorize
    def quick_run(self) -> None:
        """One click: inspect (if needed), authorize the target, start the chosen test."""
        self._proceed("run")

    def _proceed(self, action: str) -> None:
        if not self.confirm_box.isChecked():
            self.inspect_banner.show_message("ضع علامة على تأكيد الملكية/التصريح أولاً.", "warn")
            return
        if self.inspection is None:
            self._pending_action = action
            self.inspect()
            return
        if not self.inspection.ok:
            return
        target = self.save_target()
        if target is None:
            return
        if action == "run":
            page, test_type = self.test_combo.currentData()
            self.app.navigate(page, test_type=TestType(test_type), target_id=target.id, autostart=True)

    def save_target(self) -> AuthorizedTarget | None:
        result = self.inspection
        if result is None or not result.ok:
            return None
        if result.network_class != "public" and not self.private_box.isChecked():
            self.inspect_banner.show_message(
                "هذا عنوان محلي/داخلي. اختر «خادم محلي أو تجريبي على جهازي أو شبكتي» من قائمة "
                "«علاقتك بالموقع» ثم اضغط مرة أخرى.", "warn")
            return None
        env_choice = self.env_combo.currentData()
        if env_choice:
            environment = Environment(env_choice)
        else:
            environment = {"loopback": Environment.LOCALHOST, "private": Environment.STAGING}.get(
                result.network_class, Environment.PRODUCTION)
        try:
            target = build_target(
                url=result.base_url,
                name=self.name_edit.text().strip() or result.host,
                environment=environment,
                authorization_statement=self.statement_edit.toPlainText(),
                confirmed=self.confirm_box.isChecked(),
                resolved_ips=result.ips,
                description=self.description_edit.text(),
                allow_private=self.private_box.isChecked(),
                allowed_paths=[p.strip() for p in self.paths_edit.text().split(",")],
                allowed_methods=[m for m, box in self.method_boxes.items() if box.isChecked()],
                verify_tls=not self.tls_box.isChecked(),
            )
        except (ScopeError, TargetError) as exc:
            self.inspect_banner.show_message(str(exc), "error")
            return None
        container = self.app.container
        target = container.repo.save_target(target)
        container.audit.record("target_authorized", target=target.base_url, environment=target.environment.value,
                               network_class=target.network_class, paths=target.allowed_paths,
                               methods=target.allowed_methods, statement=target.authorization_statement)
        self.inspect_banner.show_message(f"تم حفظ الهدف «{target.name}» كهدف مصرّح به.", "ok")
        self.confirm_box.setChecked(False)  # every new authorization needs a fresh confirmation
        self.name_edit.clear()
        self.app.controller.data_changed.emit()
        self._select_target(target.id)
        return target

    # --------------------------------------------------------------- targets
    def refresh_targets(self) -> None:
        selected = self._selected_target_id()
        self._targets = self.app.container.repo.list_targets()
        fill_table(self.targets_table, [[
            t.name, t.base_url, ENVIRONMENT_LABELS[t.environment.value],
            NETWORK_LABELS.get(t.network_class, t.network_class),
            "محلي موثوق" if t.is_local else ("موثّقة" if t.ownership_verified else "غير موثّقة"),
            ", ".join(t.allowed_paths), ", ".join(t.allowed_methods),
        ] for t in self._targets], {4: ["#4ade80" if t.is_trusted else "#fbbf24" for t in self._targets]})
        typed = self.url_edit.text()
        self.url_combo.blockSignals(True)
        self.url_edit.blockSignals(True)
        self.url_combo.clear()
        for target in self._targets:
            self.url_combo.addItem(target.base_url)
        self.url_combo.setCurrentIndex(-1)
        self.url_edit.setText(typed)
        self.url_edit.blockSignals(False)
        self.url_combo.blockSignals(False)
        self._select_target(selected)
        self._update_target_actions()

    def _selected_target_id(self) -> int | None:
        model = self.targets_table.selectionModel()
        rows = model.selectedRows() if model else []
        return self._targets[rows[0].row()].id if rows and rows[0].row() < len(self._targets) else None

    def _select_target(self, target_id: int | None) -> None:
        for index, target in enumerate(self._targets):
            if target.id == target_id:
                self.targets_table.selectRow(index)
                return

    def selected_target(self) -> AuthorizedTarget | None:
        return self.app.container.repo.get_target(self._selected_target_id())

    def _update_target_actions(self) -> None:
        target = self.selected_target()
        has = target is not None
        for quick in self.quick_buttons:
            quick.setEnabled(has)
            quick.setToolTip("" if has else "اختر هدفاً من الجدول أولاً")
        self.delete_button.setEnabled(has)
        self.verify_button.setEnabled(has and not target.is_local and not target.ownership_verified)
        if has and target.is_local:
            self.verify_button.setToolTip("الهدف المحلي (loopback) موثوق تلقائياً")
        elif has and target.ownership_verified:
            self.verify_button.setToolTip("تم توثيق ملكية هذا الهدف")

    def _launch(self, page: str, test_type: TestType) -> None:
        target = self.selected_target()
        if target is not None:
            self.app.navigate(page, test_type=test_type, target_id=target.id)

    def _delete_target(self) -> None:
        target = self.selected_target()
        if target is None:
            return
        if confirm(self, "حذف الهدف", f"حذف الهدف «{target.name}» من قائمة الأهداف المصرّح بها؟\n"
                                      "سجل الاختبارات السابقة لن يُحذف.", "حذف"):
            self.app.container.repo.delete_target(target.id)
            self.app.container.audit.record("target_deleted", target=target.base_url)
            self.app.controller.data_changed.emit()

    def _open_verify_dialog(self) -> None:
        target = self.selected_target()
        if target is not None:
            VerifyOwnershipDialog(self.app, target, self).exec()


class VerifyOwnershipDialog(QDialog):
    """Explains the two ownership proofs and checks them in the background."""

    def __init__(self, app: AppContext, target: AuthorizedTarget, parent: QWidget) -> None:
        super().__init__(parent)
        self.app, self.target = app, target
        self.setWindowTitle("توثيق ملكية الهدف")
        self.setMinimumWidth(640)
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.addWidget(label(
            f"لتوثيق ملكية «{target.base_url}» نفّذ إحدى الطريقتين ثم اضغط «تحقق». "
            "الهدف الموثّق يمكنه استخدام الحدود المرفوعة والتقييمات الحساسة.", wrap=True))
        http_card = Card("الطريقة 1: ملف على الموقع")
        http_card.add(label("أنشئ ملفاً نصياً على هذا المسار ومحتواه هو الرمز فقط:", "Hint"))
        http_card.add(self._copyable(target.base_url + verification_path(target.verify_token)))
        http_card.add(self._copyable(target.verify_token))
        layout.addWidget(http_card)
        dns_card = Card("الطريقة 2: سجل DNS من نوع TXT")
        dns_card.add(label(f"أضف سجل TXT على _sentinel-verify.{target.host} (أو على النطاق نفسه) بالقيمة:", "Hint"))
        dns_card.add(self._copyable(verification_txt_value(target.verify_token)))
        layout.addWidget(dns_card)
        self.banner = Banner()
        layout.addWidget(self.banner)
        self.http_button = button("تحقق عبر الملف", "Primary")
        self.dns_button = button("تحقق عبر DNS")
        close = button("إغلاق")
        self.http_button.clicked.connect(lambda: self._verify("http"))
        self.dns_button.clicked.connect(lambda: self._verify("dns"))
        close.clicked.connect(self.accept)
        layout.addLayout(row(self.http_button, self.dns_button, 1, close))

    def _copyable(self, text: str) -> QWidget:
        holder = QWidget()
        line = QLineEdit(text)
        line.setReadOnly(True)
        line.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        line.setAlignment(Qt.AlignmentFlag.AlignLeft)
        copy = button("نسخ")
        copy.clicked.connect(lambda: QApplication.clipboard().setText(text))
        inner = QHBoxLayout(holder)
        inner.setContentsMargins(0, 0, 0, 0)
        inner.addWidget(line, 1)
        inner.addWidget(copy)
        return holder

    def _verify(self, method: str) -> None:
        self.http_button.setEnabled(False)
        self.dns_button.setEnabled(False)
        self.banner.show_message("جارٍ التحقق…", "info")
        check = verify_ownership_http if method == "http" else verify_ownership_dns
        run_async(lambda: check(self.target), lambda ok: self._done(bool(ok), method),
                  lambda message: self._done(False, method, message))

    def _done(self, verified: bool, method: str, error: str = "") -> None:
        self.http_button.setEnabled(True)
        self.dns_button.setEnabled(True)
        container = self.app.container
        container.audit.record("ownership_verification", target=self.target.base_url, method=method,
                               verified=verified)
        if verified:
            self.target.ownership_verified = True
            container.repo.save_target(self.target)
            self.banner.show_message("تم توثيق الملكية بنجاح.", "ok")
            self.app.controller.data_changed.emit()
        else:
            self.banner.show_message(
                "لم يُعثر على الرمز. تأكد من نشر الملف/السجل ثم أعد المحاولة." + (f" ({error})" if error else ""),
                "error")


__all__ = ["NewTestPage", "VerifyOwnershipDialog", "NOT_AVAILABLE", "Badge"]
