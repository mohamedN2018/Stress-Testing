"""Request bodies and multi-step scenarios for the load engines.

A scenario is what one virtual user repeats, in order, with its own cookies::

    POST /accounts/login/ username=qa-user&password=qa-pass
    GET /dashboard/
    POST /api/items {"name": "load test"}

Bodies may hold a test account's credentials, so they are run-time only: they
live under ``_``-prefixed keys of ``TestConfig.extra`` (never persisted) and
only the step list without bodies is written to the history and the reports.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

MAX_STEPS = 10
MAX_BODY_BYTES = 64 * 1024
METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE")
BODY_METHODS = ("POST", "PUT", "PATCH", "DELETE")
CONTENT_TYPES = {
    "form": "application/x-www-form-urlencoded",
    "json": "application/json",
    "text": "text/plain; charset=utf-8",
}


@dataclass(frozen=True)
class Step:
    method: str
    path: str
    body: str = ""
    body_type: str = ""

    @property
    def label(self) -> str:
        return f"{self.method} {self.path}"

    def to_dict(self) -> dict[str, str]:
        return {"method": self.method, "path": self.path, "body": self.body, "body_type": self.body_type}


def body_type_of(body: str) -> str:
    """'json' for {...}/[...], 'form' for a=b&c=d, otherwise 'text'; '' when there is no body."""
    text = body.strip()
    if not text:
        return ""
    if text[0] in "{[":
        return "json"
    return "form" if "=" in text else "text"


def parse_scenario(text: str) -> list[Step]:
    """One step per line: ``METHOD /path [body]``. Raises ValueError (Arabic) on a bad line."""
    steps: list[Step] = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        method = parts[0].upper()
        if method not in METHODS or len(parts) < 2 or not parts[1].startswith("/"):
            raise ValueError(f"السيناريو، السطر {number}: الصيغة هي «METHOD /path [body]» مثل: POST /login user=qa&pass=x")
        body = parts[2].strip() if len(parts) > 2 else ""
        if body and method not in BODY_METHODS:
            raise ValueError(f"السيناريو، السطر {number}: الطريقة {method} لا تحمل body.")
        steps.append(Step(method, parts[1], body, body_type_of(body)))
    if len(steps) > MAX_STEPS:
        raise ValueError(f"السيناريو: الحد الأقصى {MAX_STEPS} خطوات.")
    return steps


def steps_from_extra(extra: dict[str, Any]) -> list[Step]:
    """Scenario steps stored in ``extra['_scenario']`` (empty list when there is none)."""
    steps: list[Step] = []
    for item in extra.get("_scenario") or []:
        if isinstance(item, Step):
            steps.append(item)
        elif isinstance(item, dict):
            steps.append(Step(str(item.get("method", "GET")).upper(), str(item.get("path", "/")),
                              str(item.get("body", "")), str(item.get("body_type", ""))
                              or body_type_of(str(item.get("body", "")))))
        else:
            raise ValueError("خطوة سيناريو غير صالحة.")
    return steps


def describe_steps(steps: list[Step]) -> str:
    """Step list without bodies: safe to persist and to print in reports."""
    return " ← ".join(step.label.partition("?")[0] for step in steps)
