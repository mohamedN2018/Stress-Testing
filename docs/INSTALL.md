# التثبيت والتشغيل — Sentinel Test Lab

## الطريقة 1: الملف التنفيذي الجاهز (الأسهل)

لا تحتاج Python.

1. افتح المجلد `dist\SentinelTestLab\`.
2. شغّل `SentinelTestLab.exe` (أو الاختصار `Sentinel Test Lab` في جذر المشروع).

لنقل التطبيق إلى جهاز آخر انسخ المجلد `dist\SentinelTestLab` **كاملاً** (الملف `.exe` وحده لا يكفي؛
مجلد `_internal` بجواره جزء منه).

> قد يعرض Windows SmartScreen تحذيراً عند أول تشغيل لأن الملف غير موقّع رقمياً:
> اختر «More info» ثم «Run anyway».

## الطريقة 2: التشغيل من الكود المصدري

المتطلبات: Windows 11 و [uv](https://docs.astral.sh/uv/) (أو Python 3.12 / 3.13).

```powershell
cd "F:\4_docker-composer\Django Project\1-Online\sentinel-test-lab"

# مرة واحدة: إنشاء البيئة وتثبيت التبعيات
uv python install 3.12
uv venv --python 3.12 .venv
uv pip install --python .venv\Scripts\python.exe -r requirements-dev.txt

# التشغيل
.venv\Scripts\python.exe run_sentinel.py
```

بدون uv: `py -3.12 -m venv .venv` ثم `.venv\Scripts\pip install -r requirements-dev.txt`.

> Python 3.14 غير مدعوم حالياً (PySide6 لا يوفّر له حزماً بعد).

## أين تُحفظ البيانات؟

`%APPDATA%\SentinelTestLab\`

| المسار | المحتوى |
|---|---|
| `sentinel.db` | الأهداف، سجل الاختبارات، الإعدادات، سجل التدقيق |
| `logs\sentinel.log` | سجل التطبيق (JSON) |
| `logs\audit.jsonl` | سجل التدقيق |
| `reports\` | المكان الافتراضي لحفظ التقارير |
| `work\` | ملفات مؤقتة لـ Locust و k6 |

لاستخدام مجلد آخر: `SentinelTestLab.exe --data-dir D:\SentinelData` أو متغير البيئة `SENTINEL_DATA_DIR`.

## التجربة الأولى (على خادم محلي آمن)

```powershell
# نافذة 1: خادم تجريبي محلي على المنفذ 8765
.venv\Scripts\python.exe -m tests.support.local_server 8765
```

ثم في التطبيق:

1. **اختبار جديد** ← اكتب `http://127.0.0.1:8765` في «عنوان الموقع».
2. من «علاقتك بالموقع» اختر «خادم محلي أو تجريبي على جهازي أو شبكتي»، ومن «نوع الاختبار» اختر ما تريد.
3. ضع علامة تأكيد الملكية ← اضغط **«فحص وتشغيل»**. التطبيق يفحص الهدف ويحفظه ويبدأ الاختبار مباشرةً.
4. بعد الانتهاء: «عرض التقرير» ← «تصدير PDF».

في المرات التالية يظهر العنوان في القائمة، فلا تحتاج لكتابة أي شيء.

مسارات مفيدة في الخادم التجريبي: `/ok`، `/slow?ms=300`، `/degrade` (يتدهور فوق 12 اتصالاً)،
`/ratelimited` (429 بعد 10 طلبات)، `/login` (قفل بعد 5 محاولات)، `/secure` (ترويسات أمان كاملة).

## التكاملات الاختيارية

التطبيق يعمل كاملاً بدونها. فعّلها من **الإعدادات**:

| الأداة | التثبيت | الإعداد |
|---|---|---|
| k6 | `winget install --id GrafanaLabs.k6 --source winget` | لا شيء: يُكتشف تلقائياً |
| OWASP ZAP | `winget install --id ZAP.ZAP --source winget` (يتطلب Java 17+) | لا شيء: يُشغَّل تلقائياً عند اختيار فحص ZAP |
| Locust | `pip install locust` | يُكتشف تلقائياً من PATH، أو حدّد المسار |
| Cloudflare | أنشئ API token بصلاحية «Zone → Read» فقط | الصق الـ token في الإعدادات |
| مراقبة حاوية Docker | Docker Desktop محلياً، أو خادمك عبر `ssh` بمفتاح | الإعدادات ← «اكتشاف الحاويات» ← اختر حاوية الموقع |

**على هذا الجهاز k6 v2.4.0 و ZAP 2.17.0 مثبتان ومُختبَران.**

لاستخدام ZAP يعمل على جهاز آخر بدل المحلي، ضع عنوانه ومفتاحه في الإعدادات («ZAP daemon خارجي»).

## تشغيل الاختبارات

```powershell
.venv\Scripts\python.exe -m pytest tests -q
```

## بناء الملف التنفيذي

```powershell
.venv\Scripts\pyinstaller.exe sentinel.spec --noconfirm
dist\SentinelTestLab\SentinelTestLab.exe --selftest   # كود الخروج 0 = سليم

# فحص كامل: اختبار حمل حقيقي + تصدير التقارير من داخل الـ exe (على loopback فقط)
.venv\Scripts\python.exe -m tests.support.local_server 8765   # في نافذة أخرى
dist\SentinelTestLab\SentinelTestLab.exe --selftest-url http://127.0.0.1:8765/ok --selftest-out result.json
```

لإعادة توليد الأيقونة: `.venv\Scripts\python.exe scripts\make_icon.py`.
