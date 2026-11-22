"""Small reusable widgets shared by all pages."""

from __future__ import annotations

from typing import Any, Iterable

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLayout,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...core.i18n import NOT_AVAILABLE, SEVERITY_LABELS
from ...core.models import Finding

SEVERITY_COLORS = {"high": "#f87171", "medium": "#fbbf24", "low": "#60a5fa", "info": "#94a3b8"}
STATUS_TONES = {"completed": "good", "stopped": "", "auto_stopped": "warn", "failed": "bad", "running": "info"}


def restyle(widget: QWidget, **properties: Any) -> None:
    """Set dynamic properties and re-apply the stylesheet so they take effect."""
    changed = False
    for name, value in properties.items():
        if widget.property(name) != value:
            widget.setProperty(name, value)
            changed = True
    if changed:
        widget.style().unpolish(widget)
        widget.style().polish(widget)


def label(text: str = "", object_name: str = "", wrap: bool = False, selectable: bool = False) -> QLabel:
    widget = QLabel(text)
    if object_name:
        widget.setObjectName(object_name)
    widget.setWordWrap(wrap)
    if selectable:
        widget.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return widget


def button(text: str, object_name: str = "", tooltip: str = "") -> QPushButton:
    widget = QPushButton(text)
    if object_name:
        widget.setObjectName(object_name)
    if tooltip:
        widget.setToolTip(tooltip)
    widget.setCursor(Qt.CursorShape.PointingHandCursor)
    return widget


class Card(QFrame):
    """A titled surface that groups related controls."""

    def __init__(self, title: str = "", subtitle: str = "") -> None:
        super().__init__()
        self.setObjectName("Card")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(16, 14, 16, 16)
        self.body.setSpacing(10)
        if title:
            self.title_label = label(title, "CardTitle")
            self.body.addWidget(self.title_label)
        if subtitle:
            self.body.addWidget(label(subtitle, "Hint", wrap=True))

    def add(self, item: QWidget | QLayout, stretch: int = 0) -> None:
        if isinstance(item, QLayout):
            self.body.addLayout(item, stretch)
        else:
            self.body.addWidget(item, stretch)


class StatCard(QFrame):
    """One live metric. A missing value is shown as "unavailable", never as zero."""

    def __init__(self, title: str, unit: str = "", tooltip: str = "") -> None:
        super().__init__()
        self.setObjectName("Stat")
        self._unit = unit
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 9, 12, 10)
        layout.setSpacing(2)
        layout.addWidget(label(title, "StatTitle"))
        self.value_label = label(NOT_AVAILABLE, "StatValue")
        self.value_label.setProperty("tone", "na")
        layout.addWidget(self.value_label)
        self.setMinimumWidth(118)
        if tooltip:
            self.setToolTip(tooltip)

    def set_value(self, value: Any, tone: str = "", digits: int = 1) -> None:
        if value is None:
            self.value_label.setText(NOT_AVAILABLE)
            restyle(self.value_label, tone="na")
            return
        if isinstance(value, float):
            text = f"{value:,.{digits}f}"
        elif isinstance(value, int):
            text = f"{value:,}"
        else:
            text = str(value)
        self.value_label.setText(f"{text} {self._unit}".strip())
        restyle(self.value_label, tone=tone)

    def text(self) -> str:
        return self.value_label.text()


class Banner(QLabel):
    """Inline message strip (info / ok / warn / error)."""

    def __init__(self, text: str = "", tone: str = "info") -> None:
        super().__init__(text)
        self.setObjectName("Banner")
        self.setWordWrap(True)
        self.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.setProperty("tone", tone)
        self.setVisible(bool(text))

    def show_message(self, text: str, tone: str = "info") -> None:
        self.setText(text)
        restyle(self, tone=tone)
        self.setVisible(bool(text))


class Badge(QLabel):
    def __init__(self, text: str = "", tone: str = "") -> None:
        super().__init__(text)
        self.setObjectName("Badge")
        self.setProperty("tone", tone)
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Maximum)

    def set(self, text: str, tone: str = "") -> None:
        self.setText(text)
        restyle(self, tone=tone)


def make_table(headers: list[str], stretch_column: int = -1) -> QTableWidget:
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.verticalHeader().setVisible(False)
    table.setAlternatingRowColors(True)
    table.setShowGrid(False)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.setWordWrap(True)
    header = table.horizontalHeader()
    header.setDefaultAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
    header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    if stretch_column >= 0:
        header.setSectionResizeMode(stretch_column, QHeaderView.ResizeMode.Stretch)
    else:
        header.setStretchLastSection(True)
    return table


def fill_table(table: QTableWidget, rows: Iterable[list[Any]], colors: dict[int, list[str]] | None = None) -> None:
    """Replace the table content. ``colors`` maps column -> list of text colors per row."""
    rows = list(rows)
    table.setRowCount(len(rows))
    for r, row in enumerate(rows):
        for c, value in enumerate(row):
            item = QTableWidgetItem("" if value is None else str(value))
            item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            if colors and c in colors and colors[c][r]:
                item.setForeground(QColor(colors[c][r]))
            table.setItem(r, c, item)
    table.resizeRowsToContents()


class FindingsTable(QTableWidget):
    """Findings sorted by severity with their recommendations."""

    HEADERS = ["الخطورة", "الملاحظة", "التفاصيل", "التوصية"]

    def __init__(self) -> None:
        super().__init__(0, len(self.HEADERS))
        self.setHorizontalHeaderLabels(self.HEADERS)
        self.verticalHeader().setVisible(False)
        self.setAlternatingRowColors(True)
        self.setShowGrid(False)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setWordWrap(True)
        header = self.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)

    def set_findings(self, findings: list[Finding]) -> None:
        ordered = sorted(findings, key=lambda f: -f.severity.rank)
        fill_table(
            self,
            [[SEVERITY_LABELS[f.severity.value], f.title, f.detail, f.recommendation or "—"] for f in ordered],
            {0: [SEVERITY_COLORS[f.severity.value] for f in ordered]},
        )


def scrollable(widget: QWidget) -> QScrollArea:
    area = QScrollArea()
    area.setWidgetResizable(True)
    area.setFrameShape(QFrame.Shape.NoFrame)
    area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    area.setWidget(widget)
    return area


def row(*widgets: QWidget | int, spacing: int = 8) -> QHBoxLayout:
    """Horizontal layout; an int adds a stretch with that factor."""
    layout = QHBoxLayout()
    layout.setSpacing(spacing)
    for widget in widgets:
        if isinstance(widget, int):
            layout.addStretch(widget)
        else:
            layout.addWidget(widget)
    return layout


def confirm(parent: QWidget, title: str, text: str, yes: str = "نعم", no: str = "إلغاء") -> bool:
    box = QMessageBox(parent)
    box.setWindowTitle(title)
    box.setText(text)
    box.setIcon(QMessageBox.Icon.Warning)
    yes_button = box.addButton(yes, QMessageBox.ButtonRole.AcceptRole)
    box.addButton(no, QMessageBox.ButtonRole.RejectRole)
    box.exec()
    return box.clickedButton() is yes_button


def show_error(parent: QWidget, title: str, text: str) -> None:
    QMessageBox.warning(parent, title, text)
