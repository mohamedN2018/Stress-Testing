"""Draw the application icon (shield + pulse line) and save it as ICO and PNG.

Usage:  .venv\\Scripts\\python.exe scripts\\make_icon.py
Output: sentinel_test_lab/ui/themes/app.ico and app.png
"""

from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QGuiApplication, QImage, QLinearGradient, QPainter, QPainterPath, QPen

OUT_DIR = Path(__file__).resolve().parent.parent / "sentinel_test_lab" / "ui" / "themes"


def draw(size: int = 256) -> QImage:
    image = QImage(size, size, QImage.Format.Format_ARGB32)
    image.fill(Qt.GlobalColor.transparent)
    p = QPainter(image)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    s = size / 256.0

    # background tile
    background = QLinearGradient(0, 0, 0, size)
    background.setColorAt(0, QColor("#17212b"))
    background.setColorAt(1, QColor("#0d1319"))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(background)
    p.drawRoundedRect(QRectF(8 * s, 8 * s, 240 * s, 240 * s), 52 * s, 52 * s)

    # shield
    shield = QPainterPath()
    shield.moveTo(128 * s, 44 * s)
    shield.lineTo(196 * s, 70 * s)
    shield.lineTo(196 * s, 128 * s)
    shield.cubicTo(196 * s, 172 * s, 166 * s, 200 * s, 128 * s, 214 * s)
    shield.cubicTo(90 * s, 200 * s, 60 * s, 172 * s, 60 * s, 128 * s)
    shield.lineTo(60 * s, 70 * s)
    shield.closeSubpath()
    fill = QLinearGradient(0, 44 * s, 0, 214 * s)
    fill.setColorAt(0, QColor(34, 184, 207, 70))
    fill.setColorAt(1, QColor(34, 184, 207, 18))
    p.setBrush(fill)
    p.setPen(QPen(QColor("#22b8cf"), 11 * s, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap,
                  Qt.PenJoinStyle.RoundJoin))
    p.drawPath(shield)

    # pulse / response-time line
    pulse = QPainterPath()
    points = [(78, 132), (104, 132), (116, 104), (134, 160), (148, 120), (156, 132), (178, 132)]
    pulse.moveTo(QPointF(points[0][0] * s, points[0][1] * s))
    for x, y in points[1:]:
        pulse.lineTo(QPointF(x * s, y * s))
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.setPen(QPen(QColor("#e6edf3"), 10 * s, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap,
                  Qt.PenJoinStyle.RoundJoin))
    p.drawPath(pulse)
    p.end()
    return image


def main() -> int:
    app = QGuiApplication(sys.argv)  # noqa: F841 - required for painting
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    image = draw(256)
    png, ico = OUT_DIR / "app.png", OUT_DIR / "app.ico"
    ok_png = image.save(str(png), "PNG")
    ok_ico = image.save(str(ico), "ICO")
    print(f"png={ok_png} ({png.stat().st_size if ok_png else 0} bytes)  "
          f"ico={ok_ico} ({ico.stat().st_size if ok_ico and ico.exists() else 0} bytes)")
    return 0 if ok_png and ok_ico else 1


if __name__ == "__main__":
    sys.exit(main())
