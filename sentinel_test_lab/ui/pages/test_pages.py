"""The seven test categories, each a small form on top of :class:`TestPage`."""

from __future__ import annotations

from PySide6.QtGui import QStandardItemModel
from PySide6.QtWidgets import QTabWidget, QVBoxLayout, QWidget

from ...core.config import (
    ABSOLUTE_LIMITS,
    BRUTE_FORCE_MAX_ATTEMPTS,
    BRUTE_FORCE_MIN_INTERVAL_S,
    FLOOD_MAX_DURATION_S,
    FLOOD_MAX_RPS,
)
from ...core.models import AuthorizedTarget, Backend, TestConfig, TestType
from ...core.secrets_store import CLOUDFLARE_TOKEN
from ...engines.load.engine import PRESETS
from ...engines.stress.engine import build_steps
from ...integrations.k6.adapter import find_k6
from ...integrations.locust.adapter import find_locust
from ...integrations.zap.daemon import ZapDaemon, local_daemon
from ..components.widgets import label
from ..workers import run_async
from ...core.scenario import body_type_of
from .base import AppContext, Form, TestPage, add_headers_field, add_scenario_field, split_paths

__test__ = False


class LoadTestPage(TestPage):
    test_type = TestType.LOAD
    default_name = "اختبار حمل"
    intro = "يقيس سلوك الموقع تحت عدد ثابت من المستخدمين. ابدأ بـ Baseline ثم ارفع الحمل تدريجياً."

    def build_form(self, form: Form) -> None:
        presets = [(f"{name} — {users} مستخدم", users) for name, users in PRESETS.items()]
        self.preset = form.choice("preset", "الإعداد الجاهز", [*presets, ("Custom — تحديد يدوي", 0)],
                                  "مستويات حمل جاهزة وآمنة. اختر Custom لتحديد العدد بنفسك")
        self.preset.currentIndexChanged.connect(self._apply_preset)
        form.int("users", "المستخدمون", 1, ABSOLUTE_LIMITS.max_users, 5,
                 "عدد المستخدمين الافتراضيين المتزامنين")
        form.int("duration", "المدة", 5, ABSOLUTE_LIMITS.max_duration_s, 30, "مدة الاختبار الكلية", "ث")
        form.int("ramp_up", "زمن التصعيد", 0, 300, 5, "الوقت اللازم للوصول تدريجياً إلى العدد الكامل", "ث")
        form.int("requests_per_user", "طلبات لكل مستخدم", 0, 100_000, 0,
                 "0 = بلا حد لكل مستخدم (يبقى محكوماً بالمدة وميزانية الطلبات)")
        form.float("interval", "الفاصل بين الطلبات", 0.0, 60.0, 1.0,
                   "انتظار كل مستخدم بين طلب وآخر (زمن التفكير)", "ث", step=0.1)
        self.add_request_fields(form)
        form.text("body", "جسم الطلب (اختياري)", "",
                  "يُرسَل مع كل طلب عند اختيار POST/PUT/PATCH/DELETE. form أو JSON. "
                  "لهدف موثّق الملكية. يُكتشف النوع تلقائياً",
                  "username=qa&password=x  أو  {\"q\": \"load\"}")
        add_scenario_field(form)
        self.backend = form.choice("backend", "المحرك", [("المحرك الداخلي (httpx)", Backend.INTERNAL)],
                                   "Locust و k6 اختياريان ويظهران عند تثبيتهما")
        self._apply_preset()

    def on_target_changed(self, target: AuthorizedTarget | None) -> None:
        settings = self.app.container.settings
        current = self.backend.currentData()
        self.backend.blockSignals(True)
        self.backend.clear()
        self.backend.addItem("المحرك الداخلي (httpx)", Backend.INTERNAL)
        for caption, backend, found in (("Locust", Backend.LOCUST, find_locust(settings)),
                                        ("k6", Backend.K6, find_k6(settings))):
            self.backend.addItem(caption if found else f"{caption} — غير مثبت", backend)
            if not found:
                model = self.backend.model()
                if isinstance(model, QStandardItemModel):
                    model.item(self.backend.count() - 1).setEnabled(False)
        self.backend.setCurrentIndex(max(self.backend.findData(current), 0))
        self.backend.blockSignals(False)

    def _apply_preset(self) -> None:
        users = self.preset.currentData()
        spin = self.form.widgets["users"]
        spin.setProperty("locked", bool(users))
        if users:
            spin.setValue(users)  # type: ignore[attr-defined]
        self._on_form_changed()

    def build_config(self, target: AuthorizedTarget | None) -> TestConfig:
        f = self.form
        extra: dict[str, object] = {}
        body = f.value("body")
        if body:
            extra = {"_body": body, "body_type": body_type_of(body)}
        return self.base_config(
            users=f.value("users"), duration_s=float(f.value("duration")),
            ramp_up_s=float(min(f.value("ramp_up"), f.value("duration"))),
            requests_per_user=f.value("requests_per_user"), interval_s=f.value("interval"),
            method=f.value("method") or "GET", paths=split_paths(f.value("paths")),
            rate_limit_rps=f.value("rps"), backend=Backend(f.value("backend") or "internal"),
            extra=extra)


class StressTestPage(TestPage):
    test_type = TestType.STRESS
    default_name = "اختبار إجهاد"
    intro = ("يرفع الحمل على مراحل ويتوقف تلقائياً عند أول مرحلة تتجاوز العتبات. "
             "النتيجة هي أعلى حمل تم اختباره وبقي مستقراً، وليست السعة القصوى للخادم.")

    def build_form(self, form: Form) -> None:
        form.int("start_users", "مستخدمو البداية", 1, ABSOLUTE_LIMITS.max_users, 1, "حمل المرحلة الأولى")
        form.int("step_users", "زيادة كل مرحلة", 1, 100, 1, "عدد المستخدمين المضافين في كل مرحلة")
        form.int("max_users", "أقصى مستخدمين", 1, ABSOLUTE_LIMITS.max_users, 5,
                 "لن يتجاوز الاختبار هذا العدد أبداً")
        form.int("step_duration", "مدة المرحلة", 3, 120, 10, "مدة كل مستوى حمل قبل تقييمه", "ث")
        form.float("interval", "الفاصل بين الطلبات", 0.0, 60.0, 0.5, "انتظار كل مستخدم بين الطلبات", "ث", step=0.1)
        self.add_request_fields(form)
        form.note("عتبات التوقف التلقائي (نسبة الأخطاء و p95) تُضبط من صفحة الإعدادات.")

    def _steps(self) -> int:
        f = self.form
        start, step, maximum = f.value("start_users"), f.value("step_users"), f.value("max_users")
        return 1 if maximum <= start else 1 + -(-(maximum - start) // step)

    def build_config(self, target: AuthorizedTarget | None) -> TestConfig:
        f = self.form
        duration = float(self._steps() * f.value("step_duration"))
        return self.base_config(
            users=f.value("start_users"), duration_s=duration, interval_s=f.value("interval"),
            method=f.value("method") or "GET", paths=split_paths(f.value("paths")),
            rate_limit_rps=f.value("rps"),
            extra={"start_users": f.value("start_users"), "step_users": f.value("step_users"),
                   "max_users": max(f.value("max_users"), f.value("start_users")),
                   "step_duration_s": f.value("step_duration")})

    def describe(self, config: TestConfig, target: AuthorizedTarget) -> str:
        levels = " ← ".join(str(s.users) for s in build_steps(config))
        return f"{super().describe(config, target)} المراحل (مستخدمون): {levels}."


class SpikeTestPage(TestPage):
    test_type = TestType.SPIKE
    default_name = "اختبار قفزة"
    intro = "يقارن الأداء قبل قفزة مفاجئة في الحمل وأثناءها وبعدها، ليُظهر هل يتعافى النظام."

    def build_form(self, form: Form) -> None:
        form.int("baseline_users", "مستخدمو الخط الأساسي", 1, ABSOLUTE_LIMITS.max_users, 1, "الحمل الطبيعي قبل وبعد القفزة")
        form.int("spike_users", "مستخدمو القفزة", 1, ABSOLUTE_LIMITS.max_users, 5, "الحمل أثناء القفزة")
        form.int("baseline_s", "مدة الخط الأساسي", 3, 300, 10, "", "ث")
        form.int("spike_s", "مدة القفزة", 3, 300, 10, "", "ث")
        form.int("recovery_s", "مدة مراقبة التعافي", 3, 300, 10, "", "ث")
        form.float("interval", "الفاصل بين الطلبات", 0.0, 60.0, 0.5, "", "ث", step=0.1)
        self.add_request_fields(form)

    def build_config(self, target: AuthorizedTarget | None) -> TestConfig:
        f = self.form
        duration = float(f.value("baseline_s") + f.value("spike_s") + f.value("recovery_s"))
        return self.base_config(
            users=f.value("spike_users"), duration_s=duration, interval_s=f.value("interval"),
            method=f.value("method") or "GET", paths=split_paths(f.value("paths")),
            rate_limit_rps=f.value("rps"),
            extra={"baseline_users": f.value("baseline_users"),
                   "spike_users": max(f.value("spike_users"), f.value("baseline_users")),
                   "baseline_s": f.value("baseline_s"), "spike_s": f.value("spike_s"),
                   "recovery_s": f.value("recovery_s")})


class FloodTestPage(TestPage):
    test_type = TestType.FLOOD
    default_name = "تقييم مقاومة Flood"
    start_text = "▶  بدء التقييم"
    intro = ("تقييم محدود من مصدر واحد يرصد هل يتدخل تحديد المعدل (HTTP 429). ليس أداة إغراق: "
             f"الحد الأقصى {FLOOD_MAX_RPS:g} طلب/ث لمدة {FLOOD_MAX_DURATION_S} ث، ويتوقف فور تأكد الحماية. "
             "متاح فقط لهدف محلي أو موثّق الملكية.")

    def build_form(self, form: Form) -> None:
        form.int("duration", "المدة", 3, FLOOD_MAX_DURATION_S, 10, f"بحد أقصى {FLOOD_MAX_DURATION_S} ثانية", "ث")
        form.int("users", "اتصالات متزامنة", 1, 50, 5, "عدد الاتصالات المستخدمة لبلوغ المعدل المطلوب")
        self.add_request_fields(form, rps_default=5.0, rps_max=FLOOD_MAX_RPS)

    def build_config(self, target: AuthorizedTarget | None) -> TestConfig:
        f = self.form
        return self.base_config(
            users=f.value("users"), duration_s=float(f.value("duration")), interval_s=0.0,
            method=f.value("method") or "GET", paths=split_paths(f.value("paths")),
            rate_limit_rps=f.value("rps"))


class SecurityTestPage(TestPage):
    test_type = TestType.SECURITY
    default_name = "تقييم أمني"
    start_text = "▶  بدء التقييم"
    intro = ("فحص سلبي: ترويسات الأمان، TLS، خصائص الكوكيز، تسريب معلومات الخادم ومؤشرات الإعدادات الخاطئة. "
             "لا يستغل أي ثغرة ولا يعدّل أي بيانات.")

    def build_form(self, form: Form) -> None:
        self._zap_starting = False
        self._zap_error = ""
        form.text("paths", "الصفحات", "/", "صفحات تُفحص، تفصل بينها فاصلة. أضف المعاملات لفحص المدخلات",
                  "/, /login, /search?q=test")
        add_headers_field(form)
        form.check("input_probes", "فحص معالجة المدخلات (XSS / SQL Injection / Open Redirect)", False,
                   "كشف فقط بقيم غير ضارة على معاملات الصفحات المكتوبة أعلاه. لهدف محلي أو موثّق الملكية")
        self.zap_box = form.check("use_zap", "تضمين فحص OWASP ZAP السلبي", False,
                                  "يمرّر الصفحات المحددة عبر ZAP ويقرأ تنبيهاته. يُشغَّل ZAP تلقائياً إن كان مثبتاً")
        self.zap_note = label("", "Hint", wrap=True)
        form.layout.addRow(self.zap_note)
        self.active_box = form.check(
            "active_scan", "فحص ZAP النشط (Active Scan)", False,
            "يرسل طلبات اختبارية (منها POST) إلى الموقع كله. لهدف موثوق نطاقه «كل الموقع» فقط")
        self.active_confirm = form.check(
            "active_scan_confirmed", "أصرّح صراحةً بالفحص النشط على هذا الموقع", False)
        form.int("active_duration", "أقصى مدة للفحص النشط", 30, 300, 120, "", "ث")
        self.zap_box.toggled.connect(self._sync_zap)
        self.active_box.toggled.connect(self._sync_zap)

    # ZAP is used from a configured daemon URL, or started locally on demand.
    def _zap_unavailable(self) -> str:
        if self.app.container.settings.zap_url or local_daemon().running:
            return ""
        return ZapDaemon.unavailable_reason(self.app.container.settings)

    def _needs_local_start(self) -> bool:
        return not self.app.container.settings.zap_url and not local_daemon().running

    def on_target_changed(self, target: AuthorizedTarget | None) -> None:
        reason = self._zap_unavailable()
        self.zap_box.setProperty("locked", bool(reason))
        self.zap_box.setText("تضمين فحص OWASP ZAP السلبي" if not reason else f"فحص OWASP ZAP — غير متاح ({reason})")
        if reason:
            self.zap_box.setChecked(False)
        self._sync_zap()

    def _sync_zap(self) -> None:
        zap = self.zap_box.isChecked()
        if zap and self._needs_local_start() and not self._zap_starting:
            self._start_local_zap()
        if not zap:
            self.active_box.setChecked(False)
        active = self.active_box.isChecked()
        if not active:
            self.active_confirm.setChecked(False)
        self.active_box.setProperty("locked", not zap)
        self.active_confirm.setProperty("locked", not active)
        self.form.widgets["active_duration"].setProperty("locked", not active)
        if self._zap_starting:
            self.zap_note.setText("جارٍ تشغيل ZAP محلياً… قد يستغرق حتى دقيقة في أول مرة.")
        elif self._zap_error:
            self.zap_note.setText(f"تعذّر تشغيل ZAP: {self._zap_error}")
        elif local_daemon().running:
            self.zap_note.setText(f"ZAP يعمل محلياً (الإصدار {local_daemon().version}).")
        else:
            self.zap_note.setText("بدون ZAP يعمل التقييم كاملاً بالفحوص المدمجة.")
        self._on_form_changed()

    def _start_local_zap(self) -> None:
        self._zap_starting, self._zap_error = True, ""
        container = self.app.container

        def done(_: object) -> None:
            self._zap_starting = False
            self._sync_zap()
            self.app.controller.data_changed.emit()

        def failed(message: str) -> None:
            self._zap_starting, self._zap_error = False, message.split(": ", 1)[-1]
            self.zap_box.setChecked(False)
            self._sync_zap()

        run_async(lambda: local_daemon().ensure_running(container.paths.data_dir / "zap", container.settings),
                  done, failed)

    def block_reason(self) -> str:
        if self._zap_starting:
            return "انتظر حتى يكتمل تشغيل ZAP"
        return ""

    def build_config(self, target: AuthorizedTarget | None) -> TestConfig:
        f = self.form
        active = bool(f.value("active_scan"))
        extra = {"use_zap": bool(f.value("use_zap")), "input_probes": bool(f.value("input_probes"))}
        if active:
            extra.update(active_scan=True, active_scan_confirmed=bool(f.value("active_scan_confirmed")))
        return self.base_config(users=1, duration_s=float(f.value("active_duration")) if active else 60.0,
                                interval_s=0.0, paths=split_paths(f.value("paths")), rate_limit_rps=5.0,
                                extra=extra)

    def describe(self, config: TestConfig, target: AuthorizedTarget) -> str:
        if config.extra.get("active_scan"):
            return ("جاهز: فحص ZAP النشط — يرسل ZAP عشرات إلى مئات الطلبات الاختبارية (GET و POST) "
                    "إلى الموقع كله بخيط واحد وتأخير بين الطلبات.")
        zap = " مع فحص ZAP السلبي" if config.extra.get("use_zap") else ""
        return (f"جاهز: فحص سلبي غير اقتحامي{zap}، نحو {len(config.paths) + 6} طلب قراءة فقط "
                "بمعدل لا يتجاوز 5 طلب/ث.")


class DdosPostureTestPage(TestPage):
    test_type = TestType.DDOS_POSTURE
    default_name = "تقييم الجاهزية ضد DDoS"
    start_text = "▶  بدء التقييم"
    intro = ("تقييم دفاعي لا يولّد أي حمل: يفحص وجود CDN/WAF، سلوك الكاش، تحديد المعدل ومؤشرات انكشاف "
             "الخادم الأصلي، ويقدّم توصيات. لا يمكن لأي فحص أن يثبت أن الموقع محصَّن ضد DDoS.")

    def build_form(self, form: Form) -> None:
        form.text("paths", "الصفحة المفحوصة", "/", "صفحة عامة تمثّل الموقع")
        self.cf_note = label("", "Hint", wrap=True)
        form.layout.addRow(self.cf_note)

    def on_target_changed(self, target: AuthorizedTarget | None) -> None:
        has_token = bool(self.app.container.secrets.get(CLOUDFLARE_TOKEN))
        self.cf_note.setText(
            "Cloudflare API: مُعدّ — ستُقرأ إعدادات الحماية للنطاق." if has_token else
            "Cloudflare API: غير مُعدّ — سيُعتمد على المؤشرات الظاهرة فقط. أضف token للقراءة فقط من الإعدادات.")

    def build_config(self, target: AuthorizedTarget | None) -> TestConfig:
        return self.base_config(users=1, duration_s=60.0, interval_s=0.0,
                                paths=split_paths(self.form.value("paths"))[:1], rate_limit_rps=5.0)

    def describe(self, config: TestConfig, target: AuthorizedTarget) -> str:
        return "جاهز: طلبا قراءة فقط واستعلامات DNS. لا يُرسَل أي حمل إلى الموقع."


class BruteForceTestPage(TestPage):
    test_type = TestType.BRUTE_FORCE
    default_name = "تقييم الحماية من Brute Force"
    start_text = "▶  بدء التقييم"
    intro = ("يرسل عدداً محدوداً من محاولات الدخول الفاشلة لحساب اختبار مخصص بكلمات مرور عشوائية خاطئة، "
             "ويرصد 429 أو القفل أو CAPTCHA. لا يخمّن كلمات مرور ولا يستخدم حسابات حقيقية. "
             "يتطلب هدفاً محلياً أو موثّق الملكية، وطريقة POST ضمن الطرق المسموحة.")

    def build_form(self, form: Form) -> None:
        form.text("login_path", "مسار الدخول", "/login", "مسار نموذج الدخول، مثل /accounts/login/")
        form.text("test_username", "حساب الاختبار", "", "اسم مستخدم أنشأته خصيصاً لهذا الاختبار",
                  "qa-lockout-test")
        form.int("attempts", "عدد المحاولات", 1, BRUTE_FORCE_MAX_ATTEMPTS, 8,
                 f"بحد أقصى {BRUTE_FORCE_MAX_ATTEMPTS} محاولة. يتوقف فور ظهور الحماية")
        form.float("interval", "الفاصل بين المحاولات", BRUTE_FORCE_MIN_INTERVAL_S, 30.0, 1.0, "", "ث")
        form.text("username_field", "اسم حقل المستخدم", "username", "")
        form.text("password_field", "اسم حقل كلمة المرور", "password", "")
        form.text("csrf_field", "حقل CSRF", "csrfmiddlewaretoken", "يُقرأ تلقائياً من صفحة الدخول إن وُجد (Django)")
        form.choice("content_type", "صيغة الإرسال", [("نموذج (form)", "form"), ("JSON", "json")])
        form.choice("mfa", "هل MFA مفعّل؟", [("غير محدد", "unknown"), ("نعم", "yes"), ("لا", "no")],
                    "لا يمكن اكتشافه آلياً؛ أدخله يدوياً ليظهر في التقرير")
        form.check("test_account_confirmed", "أؤكد أن هذا حساب اختبار مخصص وليس حساب مستخدم حقيقي")

    def build_config(self, target: AuthorizedTarget | None) -> TestConfig:
        f = self.form
        return self.base_config(
            users=1, duration_s=60.0, interval_s=f.value("interval"), method="POST",
            paths=[f.value("login_path") or "/login"], rate_limit_rps=2.0,
            extra={"login_path": f.value("login_path") or "/login", "test_username": f.value("test_username"),
                   "attempts": f.value("attempts"), "username_field": f.value("username_field") or "username",
                   "password_field": f.value("password_field") or "password",
                   "csrf_field": f.value("csrf_field") or "csrfmiddlewaretoken",
                   "content_type": f.value("content_type"), "mfa": f.value("mfa"),
                   "test_account_confirmed": bool(f.value("test_account_confirmed"))})

    def describe(self, config: TestConfig, target: AuthorizedTarget) -> str:
        return (f"جاهز: حتى {config.extra['attempts']} محاولة فاشلة للحساب «{config.extra['test_username']}» "
                f"بفاصل {config.interval_s:g} ث، ويتوقف فور رصد الحماية.")


class TabbedTestsPage(QWidget):
    """Groups several test categories under tabs."""

    def __init__(self, app: AppContext, pages: list[tuple[str, type[TestPage]]]) -> None:
        super().__init__()
        self.setObjectName("Page")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        self.pages: dict[TestType, TestPage] = {}
        for title, page_class in pages:
            page = page_class(app)
            self.pages[page.test_type] = page
            wrapper = QWidget()
            inner = QVBoxLayout(wrapper)
            inner.setContentsMargins(0, 12, 0, 0)
            inner.addWidget(page)
            self.tabs.addTab(wrapper, title)

    def show_type(self, test_type: TestType, target_id: int | None = None) -> None:
        page = self.pages[test_type]
        self.tabs.setCurrentIndex(list(self.pages).index(test_type))
        if target_id is not None:
            page.select_target(target_id)

