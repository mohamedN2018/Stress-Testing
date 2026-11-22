"""Starts and stops test runs for the UI and broadcasts their lifecycle."""

from __future__ import annotations

from typing import Callable

from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QInputDialog, QLineEdit, QMessageBox, QWidget

from ..app.bootstrap import Container
from ..core.models import AuthorizedTarget, RunRecord, TestConfig
from ..core.safety_manager import SafetyViolation
from ..core.test_orchestrator import PreparedRun
from .workers import run_async


class RunController(QObject):
    started = Signal(object)    # PreparedRun
    finished = Signal(object)   # RunRecord
    data_changed = Signal()     # targets / runs / settings changed: pages refresh

    def __init__(self, container: Container, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.container = container
        self._parent = parent
        self.current: PreparedRun | None = None
        # Replaceable hooks so automated tests can run without modal dialogs.
        self.ask_elevated_confirmation: Callable[[AuthorizedTarget, TestConfig], str | None] = self._ask_elevated
        self.show_rejection: Callable[[str], None] = self._show_rejection

    @property
    def running(self) -> bool:
        return self.current is not None

    def start(self, config: TestConfig, target: AuthorizedTarget, confirmed: bool) -> PreparedRun | None:
        """Authorize and launch a run. Returns None when it was refused or cancelled."""
        safety = self.container.safety
        elevated = ""
        if safety.exceeds_defaults(config):
            answer = self.ask_elevated_confirmation(target, config)
            if answer is None:
                return None
            elevated = answer
        try:
            prepared = self.container.orchestrator.prepare(
                config, target.id, confirmed=confirmed, elevated_confirmation=elevated)
        except SafetyViolation as exc:
            self.show_rejection(str(exc))
            return None
        self.current = prepared
        run_async(lambda: self.container.orchestrator.execute(prepared), self._on_finished, self._on_crashed)
        self.started.emit(prepared)
        return prepared

    def stop(self) -> None:
        """Emergency stop of the active run (no-op when idle)."""
        if self.current is not None:
            self.container.orchestrator.stop(self.current)

    def _on_finished(self, record: RunRecord) -> None:
        self.current = None
        self.finished.emit(record)
        self.data_changed.emit()

    def _on_crashed(self, message: str) -> None:
        prepared, self.current = self.current, None
        self.show_rejection(f"تعذّر إكمال التشغيل: {message}")
        if prepared is not None:
            self.finished.emit(prepared.record)
        self.data_changed.emit()

    # ------------------------------------------------------------- dialogs
    def _ask_elevated(self, target: AuthorizedTarget, config: TestConfig) -> str | None:
        text, ok = QInputDialog.getText(
            self._parent, "تأكيد الحدود المرفوعة",
            "هذه الإعدادات تتجاوز الحدود الافتراضية الآمنة (5 مستخدمين / 60 ث / 5 طلب في الثانية).\n"
            f"للتأكيد اكتب اسم المضيف بالضبط:  {target.host}",
            QLineEdit.EchoMode.Normal, "")
        return text if ok else None

    def _show_rejection(self, message: str) -> None:
        QMessageBox.warning(self._parent, "رفض محرك الأمان التشغيل", message)
