"""PDF report rendered with Qt (QTextDocument + QPdfWriter).

Qt shapes Arabic text correctly and needs no browser engine, which keeps the
packaged application small. Charts are the same SVGs as the HTML report,
rasterized with QSvgRenderer.
"""

from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtCore import QByteArray, QMarginsF, QSizeF, Qt, QUrl
from PySide6.QtGui import (
    QFont,
    QGuiApplication,
    QImage,
    QPageLayout,
    QPageSize,
    QPainter,
    QPdfWriter,
    QTextDocument,
    QTextOption,
)
from PySide6.QtSvg import QSvgRenderer

from ..core.models import RunRecord
from .html_report import build_report_context, render_template

STATUS_COLORS = {"completed": "#16a34a", "stopped": "#64748b", "auto_stopped": "#d97706",
                 "failed": "#dc2626", "running": "#2563eb"}
SEVERITY_COLORS = {"high": "#dc2626", "medium": "#d97706", "low": "#2563eb", "info": "#64748b"}
CHART_WIDTH_PX = 620
_app: QGuiApplication | None = None


def ensure_qt_application() -> None:
    """Qt text rendering needs a GUI application object.

    The native platform plugin is used so system fonts (Arabic included) are
    available. Under the ``offscreen`` plugin Qt has no system font database,
    so it is pointed at the Windows font folder.
    """
    global _app
    if QGuiApplication.instance() is None:
        if os.environ.get("QT_QPA_PLATFORM") == "offscreen":
            fonts = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Fonts"
            if fonts.is_dir():
                os.environ.setdefault("QT_QPA_FONTDIR", str(fonts))
        _app = QGuiApplication(["sentinel-report"])


def svg_to_image(svg: str, scale: float = 2.0) -> QImage:
    renderer = QSvgRenderer(QByteArray(svg.encode("utf-8")))
    size = renderer.defaultSize() * scale
    image = QImage(size, QImage.Format.Format_ARGB32)
    image.fill(Qt.GlobalColor.white)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)
    renderer.render(painter)
    painter.end()
    return image


def build_document(run: RunRecord, page_size: QSizeF | None = None) -> QTextDocument:
    """The report as a Qt rich-text document (used for the PDF and the in-app preview)."""
    ensure_qt_application()
    context = build_report_context(run)
    cards = context["cards"]
    card_rows = [cards[i:i + 4] for i in range(0, len(cards), 4)]
    chart_names = [(title, f"chart{i}.png") for i, (title, _) in enumerate(context["raw_charts"])]
    html = render_template(
        "report_pdf.html.j2", **context, card_rows=card_rows, chart_names=chart_names,
        chart_width=CHART_WIDTH_PX, status_color=STATUS_COLORS.get(context["status"], "#0f172a"),
        severity_colors=SEVERITY_COLORS,
    )
    document = QTextDocument()
    document.setDefaultFont(QFont("Segoe UI", 10))
    option = QTextOption()
    option.setTextDirection(Qt.LayoutDirection.RightToLeft)
    option.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignAbsolute)
    option.setWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)
    document.setDefaultTextOption(option)
    for (_, name), (_, svg) in zip(chart_names, context["raw_charts"]):
        document.addResource(QTextDocument.ResourceType.ImageResource, QUrl(name), svg_to_image(svg))
    if page_size is not None:
        document.setPageSize(page_size)
    document.setHtml(html)
    return document


def write_pdf(run: RunRecord, path: Path) -> Path:
    ensure_qt_application()
    writer = QPdfWriter(str(path))
    writer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
    writer.setPageMargins(QMarginsF(14, 14, 14, 14), QPageLayout.Unit.Millimeter)
    writer.setResolution(96)
    writer.setTitle(run.name)
    writer.setCreator("Sentinel Test Lab")
    paint_rect = writer.pageLayout().paintRectPixels(writer.resolution())
    document = build_document(run, QSizeF(paint_rect.size()))
    document.print_(writer)
    return path
