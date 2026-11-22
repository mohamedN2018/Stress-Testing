"""Drive the real UI against the local test server and save screenshots to docs/screenshots.

Usage:  .venv\\Scripts\\python.exe scripts\\ui_screenshots.py
Runs a real (short) load test and a security assessment through the UI controls.
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtGui import QFont  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from sentinel_test_lab import resource_path  # noqa: E402
from sentinel_test_lab.app.bootstrap import build_container  # noqa: E402
from sentinel_test_lab.core.config import AppPaths  # noqa: E402
from sentinel_test_lab.core.models import TestType  # noqa: E402
from sentinel_test_lab.core.secrets_store import MemorySecretStore  # noqa: E402
from sentinel_test_lab.ui.windows.main_window import MainWindow  # noqa: E402
from tests.support.local_server import LocalTestServer  # noqa: E402

OUT = ROOT / "docs" / "screenshots"


def pump(app: QApplication, seconds: float, until=None) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        app.processEvents()
        if until is not None and until():
            return
        time.sleep(0.01)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    server = LocalTestServer().start()
    app = QApplication(sys.argv)
    app.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
    app.setFont(QFont("Segoe UI", 10))
    app.setStyleSheet(resource_path("ui", "themes", "dark.qss").read_text(encoding="utf-8"))
    tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    container = build_container(AppPaths(Path(tmp.name)), MemorySecretStore())
    window = MainWindow(container)
    window.show()

    def shot(name: str) -> None:
        pump(app, 0.4)
        window.grab().save(str(OUT / f"{name}.png"))
        print("saved", name)

    shot("01-overview-empty")

    # --- New Test: pick from lists, tick the confirmation, save (the run is started below)
    window.navigate("new_test")
    page = window.pages["new_test"]
    page.url_edit.setText(server.url)
    page.relation_combo.setCurrentIndex(2)
    page.methods_combo.setCurrentIndex(1)
    page.confirm_box.setChecked(True)
    page.inspect()
    pump(app, 10, lambda: page.inspection is not None)
    shot("02-new-test")
    target = page.save_target()
    assert target is not None

    # --- Load test via the UI
    window.navigate("load", target_id=target.id)
    load = window.pages["load"]
    load.form.widgets["duration"].setValue(12)
    load.form.widgets["interval"].setValue(0.0)
    load.form.widgets["paths"].setText("/ok, /slow?ms=60")
    load.confirm_box.setChecked(True)
    assert load.start_button.isEnabled(), load.validation.text()
    load.start_button.click()
    pump(app, 7)
    shot("03-load-running")
    pump(app, 30, lambda: not window.controller.running)
    shot("04-load-finished")

    # --- Security assessment
    window.navigate("security", test_type=TestType.SECURITY, target_id=target.id)
    security = window.pages["security"].pages[TestType.SECURITY]
    security.confirm_box.setChecked(True)
    security.start_button.click()
    pump(app, 40, lambda: not window.controller.running)
    shot("05-security-findings")

    window.navigate("stress", test_type=TestType.STRESS, target_id=target.id)
    shot("06-stress-form")
    window.navigate("history")
    shot("07-history")
    window.navigate("reports")
    shot("08-reports")
    window.navigate("settings")
    shot("09-settings")
    window.navigate("overview")
    shot("10-overview")
    window.close()
    server.stop()


if __name__ == "__main__":
    main()
