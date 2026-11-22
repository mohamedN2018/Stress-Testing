"""Application entry point.

    python -m sentinel_test_lab.app.main            start the desktop application
    python -m sentinel_test_lab.app.main --selftest start, build every page, exit (0 = healthy)
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel-test-lab")
    parser.add_argument("--selftest", action="store_true",
                        help="start the application, build all pages, then exit")
    parser.add_argument("--data-dir", type=Path, default=None, help="use a custom data directory")
    parser.add_argument("--selftest-url", default="",
                        help="run one real default-limit test against a LOOPBACK url and export reports")
    parser.add_argument("--selftest-out", type=Path, default=None, help="write the self-test result (JSON) here")
    args, qt_args = parser.parse_known_args(argv if argv is not None else sys.argv[1:])

    if args.selftest_url:
        from .selftest import run_end_to_end

        return run_end_to_end(args.selftest_url, args.selftest_out)

    from PySide6.QtCore import Qt, QTimer
    from PySide6.QtGui import QFont
    from PySide6.QtWidgets import QApplication, QMessageBox

    from .. import APP_NAME, __version__, resource_path
    from ..core.config import AppPaths
    from ..core.secrets_store import MemorySecretStore
    from .bootstrap import build_container

    app = QApplication([sys.argv[0], *qt_args])
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(__version__)
    app.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
    app.setFont(QFont("Segoe UI", 10))
    icon_path = resource_path("ui", "themes", "app.ico")
    if icon_path.is_file():
        from PySide6.QtGui import QIcon

        app.setWindowIcon(QIcon(str(icon_path)))
    if sys.platform == "win32":  # own taskbar group and icon instead of python.exe's
        import ctypes

        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("SentinelTestLab.Desktop")
    app.setStyleSheet(resource_path("ui", "themes", "dark.qss").read_text(encoding="utf-8"))

    temp_dir: tempfile.TemporaryDirectory[str] | None = None
    try:
        if args.selftest:
            # never touch the user's real data or credentials during a self-test
            temp_dir = tempfile.TemporaryDirectory(prefix="sentinel-selftest-", ignore_cleanup_errors=True)
            container = build_container(AppPaths(Path(temp_dir.name)), MemorySecretStore())
        else:
            container = build_container(AppPaths(args.data_dir) if args.data_dir else None)
    except Exception as exc:  # noqa: BLE001 - startup failure must be visible to the user
        QMessageBox.critical(None, APP_NAME, f"تعذّر بدء التطبيق:\n{type(exc).__name__}: {exc}")
        return 1

    from ..ui.windows.main_window import NAVIGATION, MainWindow

    window = MainWindow(container)
    window.show()

    if args.selftest:
        # Fail loudly if a packaged build is missing an engine module or a bundled data file.
        from ..core.models import TestConfig, TestType
        from ..engines.registry import engine_for
        from ..reporting.html_report import _env as report_templates

        for test_type in TestType:
            engine_for(TestConfig(test_type, "selftest"))
        for template in ("report.html.j2", "report_pdf.html.j2"):
            report_templates.get_template(template)
        keys = [key for key, _, _ in NAVIGATION]

        def visit(index: int = 0) -> None:
            if index < len(keys):
                window.navigate(keys[index])
                QTimer.singleShot(60, lambda: visit(index + 1))
            else:
                window.close()
                app.quit()

        QTimer.singleShot(200, visit)

    code = app.exec()
    if temp_dir is not None:
        import logging

        logging.shutdown()  # release the log file before removing the temporary data directory
        temp_dir.cleanup()
        print(f"selftest ok: {len(NAVIGATION)} pages")
    return code


if __name__ == "__main__":
    sys.exit(main())
