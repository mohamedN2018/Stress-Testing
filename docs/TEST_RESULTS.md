# نتائج الاختبارات — Sentinel Test Lab 1.0.0

التاريخ: 2026-11-22 · Windows 11 · Python 3.12.15 · PySide6 6.10.3 · k6 2.4.0 · OWASP ZAP 2.17.0 · Locust 2.47.0

## الملخص

```
.venv\Scripts\python.exe -m pytest tests -q
194 passed in 210.20s
```

| الملف | العدد | ماذا يغطي |
|---|---|---|
| `unit/test_authorization.py` | 40 | تحليل URL، تصنيف الشبكات، قواعد التصريح، نطاق المسارات والطرق |
| `unit/test_safety_manager.py` | 43 | الحدود الافتراضية والمرفوعة والسقف المطلق، القواعد الخاصة بكل نوع، `RunGuard` |
| `unit/test_metrics_and_storage.py` | 16 | histogram، جامع المقاييس، تعدد الخيوط، SQLite والـ migrations |
| `unit/test_analyzers.py` | 11 | محللات الترويسات والكوكيز و CDN، تحليل الأداء، الملخص التنفيذي |
| `unit/test_reporting.py` | 14 | الرسوم، HTML، PDF، JSON، CSV |
| `integration/test_engines.py` | 26 | كل المحركات مقابل خادم HTTP محلي حقيقي |
| `integration/test_integrations.py` | 15 | فحص الهدف، توثيق الملكية، Locust الحقيقي، **k6 الحقيقي**، عملاء ZAP و Cloudflare |
| `integration/test_tls_dns.py` | 10 | فحص TLS مقابل خادم HTTPS محلي، توثيق الملكية وفحوص DDoS مقابل خادم DNS محلي |
| `integration/test_zap_real.py` | 3 | **ZAP الحقيقي**: تشغيل الـ daemon، الفحص السلبي، الفحص النشط |
| `integration/test_ui.py` | 16 | النافذة الحقيقية تشغّل اختبارات حقيقية (pytest-qt)، ومسار «فحص وتشغيل» بضغطة واحدة |

اختبارات التكامل ترسل طلبات HTTP حقيقية إلى `tests/support/local_server.py` على `127.0.0.1`،
وتقارن ما يعرضه التطبيق بما استلمه الخادم فعلاً. اختبارات k6 و ZAP و Locust تُتخطّى تلقائياً على جهاز
لا توجد عليه هذه الأدوات.

## التحقق من المتطلبات الأساسية

| المتطلب | الاختبار | النتيجة |
|---|---|---|
| الإيقاف الطارئ يعمل | `test_emergency_stop_within_two_seconds` | التوقف خلال أقل من 2 ث، ولا يصل أي طلب بعده |
| الإيقاف الطارئ من الواجهة | `test_load_run_from_ui_shows_real_metrics_and_emergency_stop`، `test_global_stop_button_stops_run_from_another_page` | ناجح |
| قتل العمليات الخارجية | `test_locust_emergency_stop_kills_process_tree`، `test_real_k6_emergency_stop` | لا تبقى أي عملية Locust أو k6 |
| حد المعدل مطبّق فعلاً | `test_rate_limit_is_enforced_as_seen_by_the_server` | لا توجد نافذة ثانية واحدة تتجاوز الحد، بقياس الخادم |
| ميزانية الطلبات دقيقة | `test_request_budget_is_exact` | 7 طلبات بالضبط عند ميزانية 7 |
| الإيقاف التلقائي | `test_auto_stop_when_target_returns_errors`، `test_auto_stop_when_target_is_down` | ناجح |
| رفض التشغيل غير المصرّح | `test_rejected_run_sends_nothing` ومجموعة `test_safety_manager.py` | لا يُرسَل أي طلب عند الرفض |
| لا تشغيل بلا تأكيد | `test_one_click_flow_never_starts_without_confirmation` | لا فحص ولا حفظ ولا طلبات |
| شهادة غير موثوقة لا تُقبل بصمت | `test_load_over_https_and_certificate_verification` | صفر طلبات ناجحة وإيقاف تلقائي |
| عدم متابعة redirects | `test_redirects_are_never_followed` | ناجح |
| تغيّر DNS يلغي التشغيل | `test_scope_recheck_blocks_run_when_dns_class_changed` | ناجح |
| مقاييس حقيقية | `test_load_run_records_real_metrics`، `test_real_k6_run` | إجمالي الطلبات = ما استلمه الخادم |
| لا قيم مصطنعة | `test_collector_without_samples_has_no_values`، `test_report_without_requests_shows_no_fake_numbers` | القيم غير المقاسة تظهر "غير متاح" |
| لا ادعاء سعة قصوى | `test_stress_without_limit_does_not_claim_capacity`، `test_sustainable_users_is_never_estimated` | ناجح |
| توليد التقارير | `test_export_all_formats` + `examples/` | الصيغ الأربع تُنتَج |
| الأسرار لا تُحفظ في القاعدة | `test_settings_enable_elevated_limits` | المفتاح غير موجود في ملف قاعدة البيانات |

## التحقق من الملف التنفيذي

| البند | الأمر | النتيجة |
|---|---|---|
| الإقلاع وبناء الصفحات | `SentinelTestLab.exe --selftest` | كود الخروج 0، 8 صفحات، كل المحركات والقوالب محمّلة |
| **اختبار حقيقي كامل من داخل الـ exe** | `SentinelTestLab.exe --selftest-url http://127.0.0.1:8765/ok` | 26 طلباً ناجحاً بمعدل 5.04 طلب/ث، وتصدير PDF/HTML/JSON/CSV، كود الخروج 0 |
| رفض هدف غير محلي في الفحص الذاتي | `--selftest-url https://example.com` | مرفوض (loopback فقط) |

## قياس سلوك ZAP الحقيقي

| الوضع | طلبات وصلت الخادم | المسارات |
|---|---|---|
| سلبي (نطاق `/secure`) | 2 | `/secure` فقط |
| نشط (نطاق `/secure`) | 92 خلال 23 ث (88 GET + 4 POST) | `/secure` ومسارات أخرى على مستوى الموقع |

نتيجة القياس: أُضيفت قاعدة أمان تمنع الفحص النشط إلا لهدف نطاقه الموقع كله ويسمح بـ POST.

## التحقق البصري

`scripts/ui_screenshots.py` يشغّل المسار الكامل عبر الواجهة (فحص هدف ← تصريح ← اختبار حمل ← تقييم أمني ← تقارير)
ويحفظ اللقطات في `docs/screenshots/`. روجعت اللقطات والتقرير العربي PDF (`examples/example-stress-report.pdf`):
النص العربي سليم واتجاهه RTL.

## أخطاء اكتشفتها الاختبارات وتم إصلاحها

1. **ميزانية الطلبات**: عند بلوغها كان النظام يلغي طلبات محجوزة قبل إرسالها (أُرسل 3 من 7).
2. **طلبات غير محسوبة عند التوقف**: الطلبات الملغاة وهي في الطريق لم تكن تُحصى. الآن تُحصى منفصلة (`aborted`).
3. **PDF بمربعات فارغة** تحت منصة Qt offscreen (لا خطوط نظام).
4. **تحويل الـ enum من القوائم المنسدلة**: كان حفظ الهدف يفشل.
5. **الملف التنفيذي لا يقلع**: نقطة الدخول كانت تستخدم استيراداً نسبياً.
6. **الفحص النشط خارج النطاق**: كشفه القياس على ZAP الحقيقي، وعولج بقاعدة أمان.

## ما لم يُختبر

- **Cloudflare API على حساب حقيقي** (يحتاج token من حسابك). اختُبر العميل مقابل خادم وهمي فقط.
- **أي موقع حقيقي على الإنترنت**: كل التشغيلات كانت على `127.0.0.1`. فحص CDN/DDoS وتوثيق الملكية لم يُجرَّبا على نطاق عام.
- تشغيل Locust و k6 و ZAP **من داخل الـ exe**: اختُبرت من الكود المصدري؛ الـ exe اختُبر بالمحرك الداخلي.
- أنظمة غير Windows 11، وشاشات HiDPI.

التفاصيل في `CAPABILITIES.md`.
