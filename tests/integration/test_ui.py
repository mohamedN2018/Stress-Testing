"""UI tests (pytest-qt, offscreen): the real window driving real runs against the local server."""

from __future__ import annotations

import time

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from sentinel_test_lab import resource_path
from sentinel_test_lab.app.bootstrap import build_container
from sentinel_test_lab.core.authorization import build_target
from sentinel_test_lab.core.config import AppPaths
from sentinel_test_lab.core.i18n import NOT_AVAILABLE
from sentinel_test_lab.core.models import Environment, RunStatus, TestType
from sentinel_test_lab.core.secrets_store import MemorySecretStore
from sentinel_test_lab.ui.pages import settings as settings_module
from sentinel_test_lab.ui.pages.history import compare_rows
from sentinel_test_lab.ui.windows.main_window import NAVIGATION, MainWindow
from sentinel_test_lab.ui.workers import wait_for_workers

pytestmark = pytest.mark.integration


@pytest.fixture()
def window(qtbot, tmp_path):
    app = QApplication.instance()
    app.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
    app.setStyleSheet(resource_path("ui", "themes", "dark.qss").read_text(encoding="utf-8"))
    container = build_container(AppPaths(tmp_path / "data"), MemorySecretStore())
    win = MainWindow(container)
    win.rejections = []
    win.controller.show_rejection = win.rejections.append
    win.controller.ask_elevated_confirmation = lambda target, config: target.host
    qtbot.addWidget(win)
    win.show()
    yield win
    win.controller.stop()
    wait_for_workers(10_000)
    QApplication.processEvents()


def add_target(win: MainWindow, url: str):
    target = win.container.repo.save_target(build_target(
        url=url, name="محلي", environment=Environment.LOCALHOST,
        authorization_statement="local server owned by the tester", confirmed=True,
        resolved_ips=["127.0.0.1"], allow_private=True, allowed_methods=["GET", "HEAD", "POST"]))
    win.controller.data_changed.emit()
    return target


def click_row(qtbot, table, row: int) -> None:
    """Select a row the way a user does: a real mouse click on one of its cells."""
    rect = table.visualItemRect(table.item(row, 1))
    qtbot.mouseClick(table.viewport(), Qt.MouseButton.LeftButton, pos=rect.center())


def wait_idle(qtbot, win: MainWindow, timeout: int = 30_000) -> None:
    qtbot.waitUntil(lambda: not win.controller.running, timeout=timeout)


def test_window_builds_all_pages_in_rtl(window):
    assert window.layoutDirection() == Qt.LayoutDirection.RightToLeft
    assert [title for _, title, _ in NAVIGATION] == [
        "نظرة عامة", "اختبار جديد", "اختبار الحمل", "اختبار الإجهاد", "التقييم الأمني",
        "سجل الاختبارات", "التقارير", "الإعدادات"]
    for key, title, _ in NAVIGATION:
        window.navigate(key)
        assert window.current_page_key == key and window.page_title.text() == title
        assert window.nav_buttons[key].isChecked()
    assert set(window.pages["stress"].pages) == {TestType.STRESS, TestType.SPIKE, TestType.FLOOD}
    assert set(window.pages["security"].pages) == {TestType.SECURITY, TestType.DDOS_POSTURE, TestType.BRUTE_FORCE}
    assert not window.global_stop.isVisible()


def test_start_is_blocked_without_target_or_confirmation(window, server):
    page = window.pages["load"]
    assert not page.start_button.isEnabled() and "هدف" in page.validation.text()
    add_target(window, server.url)
    assert not page.start_button.isEnabled()
    assert "تأكيد" in page.start_button.toolTip()
    page.confirm_box.setChecked(True)
    assert page.start_button.isEnabled()
    assert server.hits == []


def test_live_validation_explains_limits(window, server):
    add_target(window, server.url)
    page = window.pages["load"]
    page.confirm_box.setChecked(True)
    page.preset.setCurrentIndex(page.preset.findData(50))        # Elevated preset = 50 users
    assert not page.start_button.isEnabled()
    assert "يتجاوز الحد المسموح" in page.validation.text() and "الإعدادات" in page.validation.text()
    page.preset.setCurrentIndex(page.preset.findData(5))
    assert page.start_button.isEnabled() and page.validation.text().startswith("جاهز")
    page.form.widgets["paths"].setText("/ok, http://evil.test/")
    assert not page.start_button.isEnabled()


def test_one_click_flow_inspects_authorizes_and_starts(window, server, qtbot):
    """New Test page: only choices + one confirmation tick, then a single button does everything."""
    window.navigate("new_test")
    page = window.pages["new_test"]
    assert not page.run_button.isEnabled()                        # no URL yet
    page.url_edit.setText(server.url)
    assert not page.run_button.isEnabled() and "تأكيد" in page.run_button.toolTip()
    page.relation_combo.setCurrentIndex(2)                        # local/test server I own
    page.methods_combo.setCurrentIndex(1)                         # GET, HEAD, POST
    page.test_combo.setCurrentIndex(page.test_combo.findText("تقييم أمني"))
    page.confirm_box.setChecked(True)
    assert page.run_button.isEnabled()
    page.run_button.click()                                       # nothing else is typed or clicked

    qtbot.waitUntil(lambda: window.container.repo.counts()["runs"] == 1, timeout=20_000)
    wait_idle(qtbot, window)
    target = window.container.repo.list_targets()[0]
    assert target.base_url == server.url and target.network_class == "loopback" and target.is_trusted
    assert target.allowed_methods == ["GET", "HEAD", "POST"] and target.allowed_paths == ["/"]
    assert "خادم محلي" in target.authorization_statement and target.name == "127.0.0.1"
    run = window.container.repo.list_runs()[0]
    assert run.test_type == TestType.SECURITY and run.status == RunStatus.COMPLETED
    assert window.current_page_key == "security"
    assert window.pages["security"].pages[TestType.SECURITY].monitor.findings.rowCount() >= 5
    assert not page.confirm_box.isChecked()                       # a new authorization needs a new tick
    assert page.url_combo.findText(server.url) >= 0               # next time it is a pure selection
    events = [e["event"] for e in window.container.repo.list_audit()]
    assert "target_authorized" in events and "run_started" in events


def test_one_click_flow_never_starts_without_confirmation(window, server, qtbot):
    page = window.pages["new_test"]
    page.url_edit.setText(server.url)
    page.relation_combo.setCurrentIndex(2)
    page.quick_run()                                              # called directly, bypassing the disabled button
    qtbot.wait(300)
    assert page.inspection is None and server.hits == []
    assert window.container.repo.counts() == {"targets": 0, "runs": 0}
    assert "تأكيد" in page.inspect_banner.text()


def test_local_address_needs_the_local_choice(window, server, qtbot):
    page = window.pages["new_test"]
    page.url_edit.setText(server.url)
    page.relation_combo.setCurrentIndex(0)                        # "I own this website" (not declared local)
    page.confirm_box.setChecked(True)
    page.run_button.click()
    qtbot.waitUntil(lambda: page.inspection is not None, timeout=15_000)
    qtbot.wait(200)
    assert window.container.repo.counts() == {"targets": 0, "runs": 0}
    assert "خادم محلي" in page.inspect_banner.text() and not window.controller.running
    page.relation_combo.setCurrentIndex(2)
    page.test_combo.setCurrentIndex(page.test_combo.findText("جاهزية DDoS"))
    page.run_button.click()                                       # already inspected: proceeds immediately
    qtbot.waitUntil(lambda: window.container.repo.counts()["runs"] == 1, timeout=10_000)
    wait_idle(qtbot, window)
    assert window.container.repo.list_runs()[0].test_type == TestType.DDOS_POSTURE


def test_one_click_flow_explains_when_the_test_needs_more_input(window, server, qtbot):
    """Brute-force assessment needs a dedicated test account: the target is saved, nothing is sent."""
    page = window.pages["new_test"]
    page.url_edit.setText(server.url)
    page.relation_combo.setCurrentIndex(2)
    page.methods_combo.setCurrentIndex(1)
    page.test_combo.setCurrentIndex(page.test_combo.findText("حماية Brute Force"))
    page.confirm_box.setChecked(True)
    page.run_button.click()
    qtbot.waitUntil(lambda: window.container.repo.counts()["targets"] == 1, timeout=15_000)
    qtbot.wait(300)
    brute = window.pages["security"].pages[TestType.BRUTE_FORCE]
    assert window.current_page_key == "security" and not window.controller.running
    assert window.container.repo.counts()["runs"] == 0 and server.login_bodies == []
    assert "حساب الاختبار" in brute.validation.text() and not brute.confirm_box.isChecked()


def test_save_only_and_advanced_options(window, server, qtbot):
    window.navigate("new_test")
    page = window.pages["new_test"]
    assert not page.auth_card.isVisible()
    page.advanced_button.click()
    assert page.auth_card.isVisible()
    page.url_edit.setText(server.url)
    page.relation_combo.setCurrentIndex(2)
    page.scope_combo.setCurrentIndex(1)                           # API only
    assert page.paths_edit.text() == "/api" and page.private_box.isChecked()
    assert [m for m, b in page.method_boxes.items() if b.isChecked()] == ["GET", "HEAD"]
    page.name_edit.setText("الخادم المحلي")
    page.confirm_box.setChecked(True)
    page.save_button.click()
    qtbot.waitUntil(lambda: window.container.repo.counts()["targets"] == 1, timeout=15_000)
    target = window.container.repo.list_targets()[0]
    assert target.name == "الخادم المحلي" and target.allowed_paths == ["/api"]
    assert window.container.repo.counts()["runs"] == 0 and window.current_page_key == "new_test"
    assert window.pages["load"].target_combo.findData(target.id) >= 0


def test_unreachable_url_cannot_be_authorized(window, qtbot):
    page = window.pages["new_test"]
    page.url_edit.setText("http://127.0.0.1:9")
    page.relation_combo.setCurrentIndex(2)
    page.confirm_box.setChecked(True)
    page.run_button.click()
    qtbot.waitUntil(lambda: page.inspection is not None, timeout=20_000)
    qtbot.wait(200)
    assert not page.inspection.ok and "تعذّر" in page.inspect_banner.text()
    assert window.container.repo.counts() == {"targets": 0, "runs": 0}


def test_load_run_from_ui_shows_real_metrics_and_emergency_stop(window, server, qtbot):
    target = add_target(window, server.url)
    window.navigate("load", target_id=target.id)
    page = window.pages["load"]
    page.form.widgets["duration"].setValue(40)
    page.form.widgets["interval"].setValue(0.0)
    page.form.widgets["paths"].setText("/ok")
    page.confirm_box.setChecked(True)
    assert page.monitor.stat_text("total") == NOT_AVAILABLE       # nothing shown before a run
    page.start_button.click()
    assert window.controller.running and window.global_stop.isVisible()
    assert not page.start_button.isEnabled()
    assert not window.pages["stress"].pages[TestType.STRESS].start_button.isEnabled()

    qtbot.waitUntil(lambda: page.monitor.rps_chart.point_count("RPS") >= 2, timeout=15_000)
    page.monitor.refresh()
    shown = int(page.monitor.stat_text("total").replace(",", ""))
    assert 0 < shown <= len(server.hits)                          # the dashboard shows measured values
    assert page.monitor.stat_text("p95_ms") != NOT_AVAILABLE
    assert page.monitor.host_stats["cpu_percent"].text() != NOT_AVAILABLE
    assert page.monitor.host_stats["db"].text() == NOT_AVAILABLE  # unsupported metric is labelled

    pressed = time.monotonic()
    page.monitor.stop_button.click()
    wait_idle(qtbot, window, 5_000)
    assert time.monotonic() - pressed < 2.5
    record = window.container.repo.list_runs()[0]
    assert record.status == RunStatus.STOPPED and record.summary["total"] > 0
    assert not window.global_stop.isVisible() and not page.monitor.stop_button.isEnabled()
    assert "أوقفه المستخدم" in page.monitor.result_banner.text()
    assert not page.confirm_box.isChecked()                       # next run needs a new confirmation
    hits = len(server.hits)
    qtbot.wait(700)
    assert len(server.hits) == hits


def test_global_stop_button_stops_run_from_another_page(window, server, qtbot):
    target = add_target(window, server.url)
    page = window.pages["load"]
    page.select_target(target.id)
    page.form.widgets["duration"].setValue(40)
    page.confirm_box.setChecked(True)
    page.start_button.click()
    window.navigate("history")
    qtbot.waitUntil(lambda: len(server.hits) > 0, timeout=10_000)
    window.global_stop.click()
    wait_idle(qtbot, window, 5_000)
    assert window.container.repo.list_runs()[0].status == RunStatus.STOPPED


def test_safety_rejection_is_shown_and_nothing_is_sent(window, server):
    target = add_target(window, server.url)
    page = window.pages["load"]
    config = page.build_config(target)
    config.users = 150
    assert window.controller.start(config, target, True) is None
    assert window.rejections and "يتجاوز" in window.rejections[0]
    assert not window.controller.running and server.hits == []


def test_security_assessment_from_ui_lists_findings(window, server, qtbot):
    target = add_target(window, server.url)
    window.navigate("security", test_type=TestType.SECURITY, target_id=target.id)
    page = window.pages["security"].pages[TestType.SECURITY]
    assert not page.zap_box.isChecked() and not page.active_box.isEnabled()   # ZAP is opt-in
    page.confirm_box.setChecked(True)
    page.start_button.click()
    wait_idle(qtbot, window)
    assert page.monitor.findings.rowCount() >= 5
    assert page.monitor.tabs.currentIndex() == 1
    assert page.monitor.report_button.isVisible()


def test_history_reports_export_compare_delete(window, server, qtbot, tmp_path):
    target = add_target(window, server.url)
    page = window.pages["load"]
    page.select_target(target.id)
    page.form.widgets["duration"].setValue(5)
    page.form.widgets["interval"].setValue(0.0)
    for _ in range(2):
        page.confirm_box.setChecked(True)
        page.start_button.click()
        wait_idle(qtbot, window)
    window.navigate("history")
    history = window.pages["history"]
    assert history.table.rowCount() == 2
    history.search.setText("لا يوجد اختبار بهذا الاسم")
    assert history.table.rowCount() == 0
    history.search.clear()
    history.type_filter.setCurrentIndex(history.type_filter.findData("stress"))
    assert history.table.rowCount() == 0
    history.type_filter.setCurrentIndex(0)
    assert history.table.rowCount() == 2

    rows, _ = compare_rows(history.runs[1], history.runs[0])
    assert rows[0][0] == "إجمالي الطلبات" and rows[0][1] != NOT_AVAILABLE

    click_row(qtbot, history.table, 0)
    assert len(history.selected_runs()) == 1
    assert history.view_button.isEnabled() and not history.compare_button.isEnabled()
    history.open_report()
    reports = window.pages["reports"]
    assert window.current_page_key == "reports" and reports.run.id == history.runs[0].id
    assert "الملخص التنفيذي" in reports.preview.toPlainText()
    for fmt_name in ("pdf", "html", "json", "csv"):
        path = reports.export(fmt_name, tmp_path / f"report.{fmt_name}")
        assert path.exists() and path.stat().st_size > 500
    assert (tmp_path / "report.pdf").read_bytes().startswith(b"%PDF")

    click_row(qtbot, history.table, 0)
    assert len(history.selected_runs()) == 1
    deleted_id = history.runs[0].id
    history.delete_selected(ask=False)
    assert history.table.rowCount() == 1
    assert window.container.repo.get_run(deleted_id) is None


def test_settings_enable_elevated_limits(window, server, monkeypatch):
    target = add_target(window, server.url)
    page = window.pages["settings"]
    monkeypatch.setattr(settings_module, "confirm", lambda *a, **k: False)
    page.elevated_box.setChecked(True)
    assert not page.elevated_box.isChecked()                      # declined in the confirmation dialog
    monkeypatch.setattr(settings_module, "confirm", lambda *a, **k: True)
    page.elevated_box.setChecked(True)
    page.max_users.setValue(30)
    page.error_rate.setValue(40)
    page.zap_url.setText("127.0.0.1:8080")
    page.save()
    assert "http" in page.banner.text() and not window.container.settings.elevated_enabled
    page.zap_url.setText("http://127.0.0.1:8080")
    page.zap_key.setText("secret-key")
    page.save()
    settings = window.container.settings
    assert settings.elevated_enabled and settings.elevated_max_users == 30
    assert settings.thresholds.max_error_rate == 0.4
    assert window.container.secrets.get("zap_api_key") == "secret-key" and page.zap_key.text() == ""
    assert "secret-key" not in window.container.paths.db_path.read_bytes().decode("latin-1")
    assert window.container.safety.effective_limits(target).max_users == 30
    assert "مرفوعة" in window.safety_pill.text()
    load = window.pages["load"]
    load.preset.setCurrentIndex(load.preset.findData(25))
    assert "تتجاوز الحدود الافتراضية" in load.validation.text()
    assert any(e["event"] == "settings_changed" for e in window.container.repo.list_audit())


@pytest.mark.zap
def test_zap_starts_on_demand_from_the_security_page(window, server, qtbot):
    """Ticking the ZAP box starts the locally installed ZAP; no manual configuration."""
    from sentinel_test_lab.integrations.zap.daemon import ZapDaemon, local_daemon

    if ZapDaemon.unavailable_reason():
        pytest.skip("OWASP ZAP is not installed")
    local_daemon().stop()
    target = add_target(window, server.url)
    window.navigate("security", test_type=TestType.SECURITY, target_id=target.id)
    page = window.pages["security"].pages[TestType.SECURITY]
    try:
        assert page.zap_box.isEnabled()
        page.confirm_box.setChecked(True)
        page.zap_box.setChecked(True)
        assert not page.start_button.isEnabled() and "ZAP" in page.start_button.toolTip()   # still starting
        qtbot.waitUntil(lambda: local_daemon().running, timeout=200_000)
        qtbot.waitUntil(page.start_button.isEnabled, timeout=5_000)
        assert "يعمل محلياً" in page.zap_note.text()
        page.start_button.click()
        wait_idle(qtbot, window, 120_000)
        run = window.container.repo.list_runs()[0]
        assert run.details["zap"]["status"] == "تم" and run.details["zap"]["source"] == "local-daemon"
        assert any(f.category == "zap" for f in run.findings)
    finally:
        local_daemon().stop()
    assert not local_daemon().running
