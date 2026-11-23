"""Look of the desktop app: light/dark colour tokens, the Qt stylesheet built from them, and
painted monogram avatars. The app runs on Fusion with its own palette, so it looks the same
under any desktop (pip's Qt has no Breeze style) and follows the system light/dark setting."""

from __future__ import annotations

import string
import zlib

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QGuiApplication, QPainter, QPalette, QPixmap
from PySide6.QtWidgets import QApplication

LIGHT = {
    "window": "#f5f5f7", "sidebar": "#ebebef", "base": "#ffffff", "text": "#1d1d1f",
    "dim": "#6e6e73", "border": "#dcdce1", "hover": "rgba(0,0,0,0.045)",
    "pressed": "rgba(0,0,0,0.08)", "accent": "#007aff", "accent_text": "#ffffff",
    "field": "#e4e4e9", "good": "#248a3d", "warn": "#c93400", "toast": "rgba(30,30,32,0.92)",
    "toast_text": "#ffffff", "inactive_sel": "#d6d6dc",
}
DARK = {
    "window": "#1c1c1e", "sidebar": "#242426", "base": "#2c2c2e", "text": "#f5f5f7",
    "dim": "#98989f", "border": "#3a3a3d", "hover": "rgba(255,255,255,0.06)",
    "pressed": "rgba(255,255,255,0.1)", "accent": "#0a84ff", "accent_text": "#ffffff",
    "field": "#3a3a3d", "good": "#30d158", "warn": "#ff9f0a", "toast": "rgba(240,240,245,0.95)",
    "toast_text": "#1d1d1f", "inactive_sel": "#3e3e42",
}

# Monogram backgrounds, picked per site so an entry keeps its colour.
AVATAR_COLORS = ("#ff9500", "#ff3b30", "#af52de", "#5856d6", "#007aff", "#32ade6", "#34c759",
                 "#00c7be", "#ff2d55", "#a2845e", "#8e8e93", "#30b0c7")


MODES = ("auto", "light", "dark")


def is_dark(mode: str = "auto") -> bool:
    if mode in ("light", "dark"):
        return mode == "dark"
    try:
        scheme = QGuiApplication.styleHints().colorScheme()
        if scheme == Qt.ColorScheme.Dark:
            return True
        if scheme == Qt.ColorScheme.Light:
            return False
    except AttributeError:  # Qt < 6.5
        pass
    return QGuiApplication.palette().color(QPalette.Window).lightness() < 128


def tokens(mode: str = "auto") -> dict:
    return DARK if is_dark(mode) else LIGHT


_QSS = string.Template("""
QMainWindow, QWidget#main { background: $window; color: $text; }
QWidget { color: $text; }
QToolTip { background: $base; color: $text; border: 1px solid $border; padding: 4px 6px; }

QWidget#sidebarPane { background: $sidebar; border-right: 1px solid $border; }
QLabel#appTitle { font-size: 15pt; font-weight: 700; padding: 0 4px; }
QLabel#syncStatus { color: $dim; font-size: 9pt; padding: 0 6px; }
QLabel#syncStatus[problem="true"] { color: $warn; }

QListWidget { background: transparent; border: none; outline: none; }
QWidget#listPane { background: $base; border-right: 1px solid $border; }
QLabel#listHeader { font-size: 13pt; font-weight: 700; padding: 0 4px; }
QLabel#listCount { color: $dim; padding: 0 4px; }

QLineEdit#search {
    background: $field; border: 1px solid transparent; border-radius: 9px;
    padding: 6px 10px; selection-background-color: $accent; selection-color: $accent_text;
}
QLineEdit#search:focus { border: 2px solid $accent; padding: 5px 9px; background: $base; }

QPushButton#pill, QPushButton#pillAccent, QToolButton#pill {
    background: $field; border: none; border-radius: 8px; padding: 5px 12px; font-weight: 600;
}
QPushButton#pill:hover, QToolButton#pill:hover { background: $pressed; }
QPushButton#pill:checked { background: $accent; color: $accent_text; }
QPushButton#pill:disabled { color: $dim; }
QPushButton#pillAccent { background: $accent; color: $accent_text; }
QPushButton#pillAccent:hover { background: $accent; }
QPushButton#pillAccent:disabled { background: $field; color: $dim; }

QScrollArea#detailScroll, QWidget#detailPane { background: $window; border: none; }
QFrame#card { background: $base; border: 1px solid $border; border-radius: 12px; }
QFrame#sep { background: $border; border: none; max-height: 1px; min-height: 1px; margin-left: 16px; }
QFrame#row { background: transparent; border: none; border-radius: 0; }
QFrame#row[clickable="true"]:hover { background: $hover; }
QFrame#row[first="true"] { border-top-left-radius: 12px; border-top-right-radius: 12px; }
QFrame#row[last="true"] { border-bottom-left-radius: 12px; border-bottom-right-radius: 12px; }
QLabel#caption { color: $dim; font-size: 9pt; }
QLabel#caption[flash="true"] { color: $good; font-weight: 600; }
QLabel#value { font-size: 11pt; }
QLabel#detailTitle { font-size: 20pt; font-weight: 700; }
QLabel#detailSub { color: $dim; font-size: 11pt; }
QLabel#detailSub a { color: $accent; }
QLabel#empty { color: $dim; font-size: 11pt; }
QLabel#hint { color: $dim; font-size: 9pt; }
QPlainTextEdit#notes { background: transparent; border: none; font-size: 11pt; }

QLabel#sectionTitle { font-size: 10pt; font-weight: 700; color: $dim; padding: 0 4px; }
QLabel#pageTitle { font-size: 20pt; font-weight: 700; }
QLabel#checkIcon { font-size: 13pt; font-weight: 800; min-width: 22px; }
QLabel#checkIcon[state="ok"] { color: $good; }
QLabel#checkIcon[state="warn"] { color: $warn; }
QLabel#checkIcon[state="fail"] { color: #ff453a; }
QLabel#checkTitle { font-size: 11pt; font-weight: 600; }
QLabel#checkDetail { color: $dim; font-size: 9pt; }
QLabel#command {
    font-family: monospace; font-size: 9pt; background: $field; border-radius: 6px;
    padding: 4px 8px;
}
QLabel#summary { font-size: 11pt; font-weight: 600; }
QLabel#summary[state="ok"] { color: $good; }
QLabel#summary[state="warn"] { color: $warn; }
QLabel#summary[state="fail"] { color: #ff453a; }
QPushButton#seg { background: transparent; border: none; border-radius: 7px; padding: 5px 14px; }
QPushButton#seg:checked { background: $base; font-weight: 600; }
QFrame#segBox { background: $field; border-radius: 9px; }
QLineEdit#field {
    background: $field; border: 1px solid transparent; border-radius: 8px; padding: 5px 9px;
}
QLineEdit#field:focus { border: 2px solid $accent; padding: 4px 8px; }
QComboBox {
    background: $field; border: none; border-radius: 8px; padding: 5px 10px; min-width: 110px;
}
QComboBox QAbstractItemView { background: $base; border: 1px solid $border; selection-background-color: $accent; }

QLabel#chip { border-radius: 9px; padding: 2px 9px; font-size: 9pt; font-weight: 600; }
QLabel#chip[state="ok"] { background: rgba(48,209,88,0.16); color: $good; }
QLabel#chip[state="warn"] { background: rgba(255,159,10,0.16); color: $warn; }
QLabel#chip[state="fail"] { background: rgba(255,69,58,0.14); color: #ff453a; }
QCheckBox::indicator {
    width: 18px; height: 18px; border-radius: 5px; border: 2px solid $border; background: $base;
}
QCheckBox::indicator:checked { background: $accent; border-color: $accent; }
QCheckBox::indicator:disabled { background: $field; }

QLabel#toast {
    background: $toast; color: $toast_text; border-radius: 10px; padding: 8px 16px;
    font-weight: 600;
}

QSplitter::handle { background: transparent; width: 0px; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
QScrollBar::handle:vertical { background: $border; border-radius: 3px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: $dim; }
QScrollBar::add-line, QScrollBar::sub-line, QScrollBar::add-page, QScrollBar::sub-page {
    background: none; height: 0; }
""")


def apply(app: QApplication, mode: str = "auto") -> dict:
    """Style the whole app for `mode` (auto follows the system); returns the tokens used."""
    t = tokens(mode)
    app.setStyle("Fusion")
    pal = QPalette()
    for role, key in ((QPalette.Window, "window"), (QPalette.Base, "base"),
                      (QPalette.AlternateBase, "sidebar"), (QPalette.Text, "text"),
                      (QPalette.WindowText, "text"), (QPalette.ButtonText, "text"),
                      (QPalette.Button, "field"), (QPalette.Highlight, "accent"),
                      (QPalette.HighlightedText, "accent_text"), (QPalette.PlaceholderText, "dim"),
                      (QPalette.ToolTipBase, "base"), (QPalette.ToolTipText, "text"),
                      (QPalette.Link, "accent")):
        pal.setColor(role, QColor(t[key]))
    app.setPalette(pal)
    app.setStyleSheet(_QSS.substitute(t))
    return t


def avatar_color(key: str) -> QColor:
    return QColor(AVATAR_COLORS[zlib.crc32(key.lower().encode()) % len(AVATAR_COLORS)])


def monogram(title: str) -> str:
    for ch in title:
        if ch.isalnum():
            return ch.upper()
    return "•"


def paint_avatar(painter: QPainter, rect: QRectF, title: str, key: str) -> None:
    """A filled circle in the site's colour with the title's first letter, like the Passwords
    app's monogram icons."""
    painter.save()
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setPen(Qt.NoPen)
    painter.setBrush(avatar_color(key or title))
    painter.drawEllipse(rect)
    font = QFont(painter.font())
    font.setBold(True)
    font.setPixelSize(max(8, int(rect.height() * 0.46)))
    painter.setFont(font)
    painter.setPen(QColor("#ffffff"))
    painter.drawText(rect, Qt.AlignCenter, monogram(title))
    painter.restore()


def avatar_pixmap(title: str, key: str, size: int, dpr: float = 1.0) -> QPixmap:
    pm = QPixmap(int(size * dpr), int(size * dpr))
    pm.setDevicePixelRatio(dpr)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    paint_avatar(p, QRectF(0, 0, size, size), title, key)
    p.end()
    return pm
