"""Passive analysis of a page's HTML: forms, scripts, leaked secrets, old libraries.

Pure functions over content the site already served to an ordinary GET.
Matched secrets are never copied into the report: only their kind and a
masked prefix are recorded.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urlsplit

from ...core.models import Finding, Severity

CSRF_FIELD_NAMES = ("csrfmiddlewaretoken", "csrf_token", "_csrf", "csrf", "_token",
                    "authenticity_token", "__requestverificationtoken", "xsrf")

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("مفتاح AWS", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("مفتاح خاص (Private Key)", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("مفتاح Google API", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("مفتاح Stripe سري", re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    ("سر مضمَّن في الصفحة", re.compile(
        r"""(?i)\b(?:secret_key|api_secret|client_secret|db_password|database_password)\b\s*[:=]\s*["'][^"']{8,}["']""")),
)
PRIVATE_IP = re.compile(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b")
COMMENT_HINTS = re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|todo|fixme|debug|internal)\b")

# (library, regex capturing the version from a script URL, first safe version, why)
LIBRARY_RULES: tuple[tuple[str, re.Pattern[str], tuple[int, ...], str], ...] = (
    ("jQuery", re.compile(r"jquery[.-](\d+\.\d+(?:\.\d+)?)(?:\.min|\.slim)?\.js", re.I), (3, 5, 0),
     "إصدارات أقدم من 3.5.0 بها ثغرات XSS معروفة (CVE-2020-11022 / CVE-2020-11023)."),
    ("Bootstrap", re.compile(r"bootstrap[./@-](\d+\.\d+(?:\.\d+)?)", re.I), (3, 4, 1),
     "إصدارات أقدم من 3.4.1 بها ثغرات XSS معروفة (CVE-2019-8331)."),
    ("AngularJS", re.compile(r"angular(?:js)?[./@-](1\.\d+(?:\.\d+)?)", re.I), (2, 0, 0),
     "AngularJS 1.x انتهى دعمه ولا يتلقى إصلاحات أمنية."),
    ("Lodash", re.compile(r"lodash(?:\.min)?[./@-](\d+\.\d+(?:\.\d+)?)", re.I), (4, 17, 21),
     "إصدارات أقدم من 4.17.21 بها ثغرات Prototype Pollution معروفة."),
)


def _version(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in text.split("."))


def _mask(value: str) -> str:
    return value[:6] + "…" if len(value) > 6 else "…"


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self.scripts: list[dict[str, str]] = []
        self.stylesheets: list[dict[str, str]] = []
        self.media: list[str] = []
        self.comments: list[str] = []
        self._form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._form = {"method": a.get("method", "get").lower(), "action": a.get("action", ""),
                          "fields": [], "has_password": False}
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None:
            self._form["fields"].append(a.get("name", "").lower())
            if a.get("type", "").lower() == "password":
                self._form["has_password"] = True
        elif tag == "script" and a.get("src"):
            self.scripts.append(a)
        elif tag == "link" and "stylesheet" in a.get("rel", "").lower() and a.get("href"):
            self.stylesheets.append(a)
        elif tag in ("img", "iframe", "audio", "video", "source") and a.get("src"):
            self.media.append(a["src"])

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None

    def handle_comment(self, data: str) -> None:
        self.comments.append(data)


def analyze_html(html: str, is_https: bool, host: str, path: str = "/") -> list[Finding]:
    """Findings for one HTML document served at ``path`` of ``host``."""
    parser = _PageParser()
    try:
        parser.feed(html[:400_000])
    except Exception:  # malformed markup must never break the assessment
        return []
    findings: list[Finding] = []

    def external(url: str) -> bool:
        netloc = urlsplit(url if "://" in url else "https:" + url if url.startswith("//") else "").netloc
        return bool(netloc) and netloc.split(":")[0].lower() != host.lower()

    # --- forms
    for form in parser.forms:
        if form["method"] == "post" and not any(
                any(name in field for name in CSRF_FIELD_NAMES) for field in form["fields"]):
            findings.append(Finding(
                Severity.MEDIUM, "webapp", "نموذج POST بدون رمز حماية CSRF ظاهر",
                "لم يُعثر على حقل CSRF مخفي في النموذج؛ قد يمكن لموقع آخر إرسال الطلب باسم المستخدم.",
                "فعّل حماية CSRF (في Django: {% csrf_token %} و CsrfViewMiddleware). "
                "تجاهل الملاحظة إن كان الرمز يُرسَل في ترويسة عبر JavaScript.",
                f"{path} — action: {form['action'] or '(نفس الصفحة)'}", "CWE-352", "A01"))
        if form["has_password"] and (not is_https or form["action"].lower().startswith("http://")):
            findings.append(Finding(
                Severity.HIGH, "webapp", "نموذج كلمة مرور يُرسَل بدون تشفير",
                "كلمة المرور تنتقل كنص صريح ويمكن التقاطها على الشبكة.",
                "قدّم صفحة الدخول وأرسل النموذج عبر HTTPS فقط.", path, "CWE-319", "A02"))

    # --- mixed content
    if is_https:
        insecure = [u for u in [s["src"] for s in parser.scripts] + [s["href"] for s in parser.stylesheets]
                    + parser.media if u.lower().startswith("http://")]
        if insecure:
            findings.append(Finding(
                Severity.MEDIUM, "webapp", "محتوى مختلط (Mixed Content) في صفحة HTTPS",
                f"{len(insecure)} مورد يُحمَّل عبر HTTP غير المشفَّر.",
                "حمّل كل الموارد عبر HTTPS وأضف CSP: upgrade-insecure-requests.",
                insecure[0][:200], "CWE-311", "A02"))

    # --- third-party scripts without Subresource Integrity
    no_sri = [s["src"] for s in parser.scripts if external(s["src"]) and not s.get("integrity")]
    if no_sri:
        findings.append(Finding(
            Severity.LOW, "webapp", "سكربتات خارجية بدون Subresource Integrity",
            f"{len(no_sri)} سكربت من نطاق خارجي بلا خاصية integrity؛ اختراق المصدر يعني اختراق صفحتك.",
            "أضف integrity و crossorigin للسكربتات الخارجية أو استضفها محلياً.",
            no_sri[0][:200], "CWE-353", "A08"))

    # --- outdated client-side libraries (from the script URL only)
    for script in parser.scripts:
        for name, pattern, safe, why in LIBRARY_RULES:
            match = pattern.search(script["src"])
            if match and _version(match.group(1)) < safe:
                findings.append(Finding(
                    Severity.MEDIUM, "components", f"مكتبة {name} قديمة ({match.group(1)})", why,
                    f"حدّث {name} إلى أحدث إصدار مدعوم.", script["src"][:200], "CWE-1104", "A06"))
                break

    # --- secrets and internal details exposed in the markup
    for label, pattern in SECRET_PATTERNS:
        match = pattern.search(html)
        if match:
            findings.append(Finding(
                Severity.HIGH, "secrets", f"{label} ظاهر في مصدر الصفحة",
                "أي زائر يستطيع قراءته من مصدر الصفحة.",
                "أزل السر من الواجهة وغيّره فوراً (اعتبره مكشوفاً)، واحفظ الأسرار في الخادم فقط.",
                f"{path} — {_mask(match.group(0))}", "CWE-798", "A07"))
    ip = PRIVATE_IP.search(html)
    if ip:
        findings.append(Finding(
            Severity.LOW, "information-disclosure", "عنوان IP داخلي ظاهر في الصفحة",
            "يكشف بنية الشبكة الداخلية.", "أزل العناوين الداخلية من الردود العامة.",
            f"{path} — {ip.group(0)}", "CWE-200", "A05"))
    hinted = [c for c in parser.comments if COMMENT_HINTS.search(c)]
    if hinted:
        findings.append(Finding(
            Severity.LOW, "information-disclosure", "تعليقات HTML قد تكشف معلومات داخلية",
            f"{len(hinted)} تعليق يحوي كلمات مثل password / secret / TODO / debug.",
            "احذف تعليقات التطوير من صفحات الإنتاج.", path, "CWE-615", "A05"))
    return findings
