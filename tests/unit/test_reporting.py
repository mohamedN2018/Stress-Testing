from __future__ import annotations

import csv
import io
import json

import pytest

from sentinel_test_lab.core.models import Finding, RunRecord, RunStatus, Severity, TestConfig, TestType
from sentinel_test_lab.reporting.charts import Line, bar_chart, line_chart, nice_ticks, run_charts
from sentinel_test_lab.reporting.export import default_filename, export_run, to_csv, to_json
from sentinel_test_lab.reporting.html_report import build_report_context, fmt, render_html


def make_run(total=120, **kw) -> RunRecord:
    series = [{"t": i + 1.0, "phase": "steady", "users": 5, "rps": 20.0, "requests": 20, "failed": 1,
               "s2xx": 19, "s3xx": 0, "s4xx": 0, "s5xx": 1, "s429": 0, "avg_ms": 30.0 + i, "p95_ms": 60.0,
               "error_rate": 0.05, "system": {"cpu_percent": 10.0 + i, "ram_percent": 40.0}} for i in range(6)]
    summary = {"total": total, "success": 114, "failed": 6, "s2xx": 114, "s3xx": 0, "s4xx": 0, "s5xx": 6,
               "s429": 0, "transport_errors": 0, "aborted": 0, "rps": 20.0, "peak_rps": 20.0, "peak_users": 5,
               "avg_ms": 32.5, "p50_ms": 30.0, "p90_ms": 55.0, "p95_ms": 60.0, "p99_ms": 80.0,
               "error_rate": 0.05, "elapsed_s": 6.0, "max_sustainable_tested_users": 5,
               "metrics_host_scope": "generator_only", "error_kinds": {}}
    params = dict(
        id=7, name="اختبار <b>تجريبي</b>", test_type=TestType.LOAD, target_id=1,
        target_url="https://example.test", status=RunStatus.COMPLETED,
        started_at="2026-01-02T03:04:05+00:00", finished_at="2026-01-02T03:04:11+00:00",
        config=TestConfig(TestType.LOAD, "x").to_dict(), summary=summary, series=series,
        details={"phases": {"steady": {"users": 5, "total": total, "rps": 20, "avg_ms": 32, "p95_ms": 60,
                                       "error_rate": 0.05}}},
        findings=[Finding(Severity.LOW, "c", "منخفضة"),
                  Finding(Severity.HIGH, "c", "عالية <script>x</script>", "d", "أصلح")])
    params.update(kw)
    return RunRecord(**params)


def test_fmt_labels_missing_values_instead_of_inventing():
    assert fmt(None) == "غير متاح" and fmt(None, "ms") == "غير متاح"
    assert fmt(0) == "0" and fmt(1234.5, "ms") == "1,234.5 ms" and fmt(True) == "نعم"


def test_nice_ticks():
    assert nice_ticks(0) == [0.0, 1.0]
    ticks = nice_ticks(187)
    assert ticks[0] == 0 and ticks[-1] >= 187 and len(ticks) <= 7


def test_charts_are_omitted_without_data():
    assert line_chart([]) == "" and bar_chart([("a", 0, "#000")]) == ""
    assert run_charts({"series": [], "summary": {}}) == []
    svg = line_chart([Line("RPS", "#00f", [(0, 1), (1, 3)])])
    assert svg.startswith("<svg") and "<path" in svg


def test_run_charts_use_recorded_series():
    titles = [t for t, _ in run_charts(make_run().to_dict())]
    assert len(titles) == 5 and any("الطلبات في الثانية" in t for t in titles)


def test_html_report_content_and_escaping():
    html = render_html(make_run())
    assert 'dir="rtl"' in html and 'lang="ar"' in html
    assert "&lt;script&gt;" in html and "<script>x" not in html      # findings are escaped
    assert "اختبار &lt;b&gt;تجريبي&lt;/b&gt;" in html
    assert html.count("<svg") == 5
    for expected in ("الملخص التنفيذي", "https://example.test", "p99", "ليست السعة القصوى",
                     "حدود هذا التقرير", "هذه قيم جهاز مولّد الحمل فقط"):
        assert expected in html, expected
    assert html.index("عالية &lt;script") < html.index("منخفضة</b>")   # sorted by severity


def test_report_never_claims_capacity_that_was_not_established():
    run = make_run()
    run.summary["max_sustainable_tested_users"] = None
    assert build_report_context(run)["sustainable"] == "لم يثبته هذا الاختبار"
    security = make_run(test_type=TestType.SECURITY)
    assert build_report_context(security)["sustainable"] is None


def test_report_without_requests_shows_no_fake_numbers():
    run = make_run(total=0, series=[], details={})
    run.summary = {"total": 0, "elapsed_s": 0.1}
    context = build_report_context(run)
    assert context["charts"] == [] and len(context["cards"]) == 1
    assert "لم تُسجَّل أي طلبات" in render_html(run)


def test_json_export_roundtrip():
    data = json.loads(to_json(make_run()))
    assert data["summary"]["total"] == 120 and data["findings"][1]["severity"] == "high"
    assert data["generator"].startswith("Sentinel Test Lab")


def test_csv_export_sections():
    rows = list(csv.reader(io.StringIO(to_csv(make_run()))))
    assert ["summary", "total", "120"] in rows
    header = next(r for r in rows if r and r[0] == "t")
    assert "cpu_percent" in header
    assert sum(1 for r in rows if r and r[0] in {"1.0", "2.0", "3.0", "4.0", "5.0", "6.0"}) == 6


@pytest.mark.parametrize("fmt_name", ["pdf", "html", "json", "csv"])
def test_export_all_formats(tmp_path, fmt_name):
    run = make_run()
    path = export_run(run, fmt_name, tmp_path / default_filename(run, fmt_name))
    data = path.read_bytes()
    assert len(data) > 500
    if fmt_name == "pdf":
        assert data.startswith(b"%PDF") and len(data) > 20_000
    if fmt_name == "csv":
        assert data.startswith(b"\xef\xbb\xbf")


def test_export_rejects_unknown_format(tmp_path):
    with pytest.raises(ValueError):
        export_run(make_run(), "docx", tmp_path / "x.docx")
