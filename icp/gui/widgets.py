"""Small widgets shared by the desktop app's pages: pill buttons, card rows and a switch."""

from __future__ import annotations

from PySide6.QtCore import QRectF, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFontDatabase, QIcon, QPainter, QPainterPath
from PySide6.QtWidgets import (QAbstractButton, QFrame, QHBoxLayout, QLabel, QPushButton,
                               QSizePolicy, QVBoxLayout, QWidget)


def icon(*names: str) -> "QIcon":
    for name in names:
        icon = QIcon.fromTheme(name)
        if not icon.isNull():
            return icon
    return QIcon()


def repolish(w: "QWidget") -> None:
    w.style().unpolish(w)
    w.style().polish(w)


def pill(text: str, tip: str = "", accent: bool = False, checkable: bool = False):
    b = QPushButton(text, objectName="pillAccent" if accent else "pill", toolTip=tip,
                    checkable=checkable, cursor=Qt.PointingHandCursor)
    b.setFocusPolicy(Qt.NoFocus)  # keep keyboard focus in the list
    return b


def rounded(painter: "QPainter", rect: "QRectF", color: "QColor", radius: float = 8) -> None:
    path = QPainterPath()
    path.addRoundedRect(rect, radius, radius)
    painter.fillPath(path, color)


class Row(QFrame):
    """One field in a card: caption over value, trailing buttons. A clickable row runs
    `on_click` (copy, mostly) and briefly shows a confirmation in its caption."""

    def __init__(self, caption: str, on_click=None, tip: str = "", mono: bool = False,
                 wrap: bool = False):
        super().__init__(objectName="row")
        self._caption, self._on_click = caption, on_click
        self.setProperty("clickable", on_click is not None)
        if on_click:
            self.setCursor(Qt.PointingHandCursor)
            self.setAttribute(Qt.WA_Hover)
            self.setToolTip(tip)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(16, 10, 12, 10)
        lay.setSpacing(8)
        col = QVBoxLayout()
        col.setSpacing(2)
        self.caption = QLabel(caption, objectName="caption")
        self.value = QLabel(objectName="value", textFormat=Qt.PlainText, wordWrap=wrap)
        self.value.setSizePolicy(QSizePolicy.Ignored if not wrap else QSizePolicy.Preferred,
                                 QSizePolicy.Preferred)
        if mono:
            f = QFontDatabase.systemFont(QFontDatabase.FixedFont)
            f.setPointSizeF(self.value.font().pointSizeF() * 1.15)
            self.value.setFont(f)
        if wrap:
            self.value.setTextInteractionFlags(Qt.TextSelectableByMouse)
        col.addWidget(self.caption)
        col.addWidget(self.value)
        lay.addLayout(col, 1)
        self._lay = lay

    def add(self, w: "QWidget") -> "QWidget":
        self._lay.addWidget(w, 0, Qt.AlignVCenter)
        return w

    def mouseReleaseEvent(self, e):
        if (self._on_click and e.button() == Qt.LeftButton
                and self.rect().contains(e.position().toPoint())):
            self._on_click()
        super().mouseReleaseEvent(e)

    def flash(self, text: str = "Copied") -> None:
        self.caption.setText(f"✓  {text}")
        self.caption.setProperty("flash", True)
        repolish(self.caption)
        QTimer.singleShot(1500, self._unflash)

    def _unflash(self) -> None:
        self.caption.setText(self._caption)
        self.caption.setProperty("flash", False)
        repolish(self.caption)


class Card(QFrame):
    """A rounded group of rows with hairlines between the visible ones."""

    def __init__(self):
        super().__init__(objectName="card")
        self._lay = QVBoxLayout(self)
        self._lay.setContentsMargins(0, 0, 0, 0)
        self._lay.setSpacing(0)
        self._rows: list[tuple[QFrame | None, Row]] = []

    def add(self, row: Row) -> Row:
        sep = None
        if self._rows:
            sep = QFrame(objectName="sep")
            self._lay.addWidget(sep)
        self._lay.addWidget(row)
        self._rows.append((sep, row))
        return row

    def clear(self) -> None:
        for sep, row in self._rows:
            if sep is not None:
                sep.deleteLater()
            row.deleteLater()
        self._rows = []

    def show_rows(self, visible: dict) -> None:
        """`visible` maps rows to whether they show; unlisted rows keep showing."""
        shown = []
        for sep, row in self._rows:
            on = visible.get(row, True)
            row.setVisible(on)
            if sep is not None:
                sep.setVisible(on and bool(shown))
            if on:
                shown.append(row)
        for row in shown:
            row.setProperty("first", row is shown[0])
            row.setProperty("last", row is shown[-1])
            repolish(row)
        self.setVisible(bool(shown))


class Switch(QAbstractButton):
    """An on/off switch, painted in the window's accent colour."""

    def __init__(self, window, tip: str = ""):
        super().__init__(checkable=True, toolTip=tip, cursor=Qt.PointingHandCursor)
        self._w = window
        self.setFixedSize(QSize(42, 24))
        self.setFocusPolicy(Qt.NoFocus)

    def paintEvent(self, _):
        t = self._w.t
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        on = self.isChecked()
        track = QColor(t["good"] if on else t["border"])
        if not self.isEnabled():
            track.setAlpha(90)
        p.setPen(Qt.NoPen)
        p.setBrush(track)
        p.drawRoundedRect(QRectF(0, 0, 42, 24), 12, 12)
        p.setBrush(QColor("#ffffff"))
        p.drawEllipse(QRectF(20 if on else 2, 2, 20, 20))
