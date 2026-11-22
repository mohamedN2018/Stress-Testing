# البنية المعمارية — Sentinel Test Lab

موجّهة للمطوّر الذي سيصون المشروع أو يوسّعه.

## الطبقات

```
ui/  ──►  core/test_orchestrator  ──►  engines/*  ──►  engines/http_runner  ──►  الهدف
              │        │                    │
              │        └── core/safety_manager (بوابة الترخيص + RunGuard)
              ├── core/metrics_collector  ◄── تسجيل كل طلب
              ├── database/repository     (SQLite)
              └── reporting/*             (تحليل + تقارير)
```

القاعدة: **الواجهة لا تتصل بالشبكة أبداً**، والمحركات لا تعرف شيئاً عن Qt.

| المجلد | المسؤولية |
|---|---|
| `app/` | `main.py` نقطة الدخول؛ `bootstrap.py` يبني الخدمات ويربطها (`Container`) |
| `core/` | النماذج، الإعدادات والحدود، التصريح والنطاق، محرك الأمان، المقاييس، الـ orchestrator، التدقيق، الأسرار |
| `engines/` | محرك لكل نوع اختبار + `http_runner.py` المشترك + `registry.py` |
| `integrations/` | Locust، k6، ZAP، Cloudflare، وتشغيل العمليات الخارجية بأمان |
| `monitoring/` | histogram لزمن الاستجابة، مقاييس الجهاز (psutil) |
| `reporting/` | تحليل الاختناقات، الرسوم (SVG)، HTML، PDF، JSON/CSV |
| `database/` | اتصال SQLite، migrations مرقّمة، repository |
| `ui/` | النافذة، الصفحات، المكوّنات، الثيم، العمل في الخلفية |

## مسار تشغيل اختبار

1. الصفحة تبني `TestConfig` وتستدعي `RunController.start`.
2. `TestOrchestrator.prepare` (على خيط الواجهة، بلا شبكة):
   `SafetyManager.authorize_run` ← ينشئ `MetricsCollector` و `RunGuard` ← يحفظ التشغيل بحالة running.
3. `AsyncWorker` (QThread) يشغّل `TestOrchestrator.execute` على event loop خاص به:
   إعادة فحص DNS ← اختيار المحرك ← تشغيله مع مهمة sampler (تقييم كل 250ms، عيّنة كل ثانية).
4. المحرك يرسل الطلبات عبر `HttpRunner` أو `ScopedHttp`؛ كل طلب يمر على `RunGuard.acquire`
   (ميزانية + معدل) ثم يُسجَّل في `MetricsCollector`.
5. الواجهة تقرأ `metrics.snapshot()` بمؤقّت كل 500ms (لا إشارات لكل طلب).
6. عند الانتهاء: `_finalize` يحدد الحالة، يضيف تحليل الأداء، ويحفظ التشغيل.

## الخيوط (Threads)

| الخيط | ما يعمل عليه |
|---|---|
| خيط الواجهة | Qt، قراءة snapshots، SQLite (عمليات قصيرة)، توليد PDF |
| خيط عامل لكل مهمة | asyncio loop: المحركات، فحص الهدف، توثيق الملكية، فحص ZAP |

`MetricsCollector` و `RunGuard` آمنان بين الخيوط (أقفال). الإيقاف الطارئ يضبط `threading.Event`
من خيط الواجهة ويلتقطه المحرك خلال ≤ 50ms.

## إضافة نوع اختبار جديد

1. أضف قيمة إلى `TestType` في `core/models.py` وتسميتها في `core/i18n.py`.
2. اكتب محركاً فيه `async def run(self, ctx: EngineContext) -> EngineOutcome` واستخدم `HttpRunner`
   أو `ScopedHttp` (لا تنشئ طلبات HTTP خارجهما حتى تبقى الحدود مطبّقة).
3. سجّله في `engines/registry.py`.
4. إن كان حساساً: أضف قواعده في `SafetyManager._authorize`.
5. أضف صفحة في `ui/pages/test_pages.py` (صنف صغير يرث `TestPage`) وجدول تفاصيله في `reporting/html_report.py`.
6. أضف endpoint مناسباً في `tests/support/local_server.py` واختبار تكامل.

## قاعدة البيانات

SQLite بوضع WAL. الجداول: `targets`، `runs`، `audit`، `settings`.
الـ migrations ملفات `NNNN_name.sql` في `database/migrations/` تُطبَّق بالترتيب حسب `PRAGMA user_version`.
لإضافة تغيير: أنشئ `0002_....sql` ولا تعدّل ملفاً سابقاً.

## قرارات تصميم

- **PDF عبر `QTextDocument`** بدل محرك متصفح: يدعم تشكيل العربية ويبقي حجم التطبيق صغيراً، مقابل CSS محدود.
- **الرسوم SVG بلا مكتبات**: نفس الرسم يُضمَّن في HTML ويُحوَّل صورة للـ PDF.
- **حقن التبعيات يدوياً** عبر `Container`: لا إطار DI، والاختبارات تبدّل `SecretStore` ومصنع المحركات بسهولة.
- **السقوف المطلقة ثوابت في الكود** (`core/config.py`): لا يمكن تجاوزها بتعديل قاعدة البيانات.
- **Locust/k6 عمليات خارجية**: Locust يعتمد gevent ولا يصلح للتضمين داخل تطبيق Qt.
