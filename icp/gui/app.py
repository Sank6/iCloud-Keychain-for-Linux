"""Desktop app for browsing the local vault (`icp-gui`). Read-only and offline, like `icp show`:
it reads the same encrypted vault and Hide My Email cache, and `Sync now` runs `icp sync` in a
child process so pacing, locking and backoff stay in one place. Signing in stays in the terminal
(`icp login`) - its passcode step is irreversible after too many wrong tries.

Needs PySide6: pip install -e '.[gui]'"""

from __future__ import annotations

import os
import sys
import time

try:
    from PySide6.QtCore import (QMimeData, QProcess, QProcessEnvironment, QRectF, QSettings, QSize,
                                Qt, QTimer, QUrl)
    from PySide6.QtGui import (QAction, QColor, QDesktopServices, QFont, QFontDatabase,
                               QGuiApplication, QIcon, QKeySequence, QPainter, QPainterPath,
                               QPen)
    from PySide6.QtWidgets import (QApplication, QFrame, QHBoxLayout, QLabel, QLineEdit,
                                   QListWidget, QListWidgetItem, QMainWindow, QMessageBox,
                                   QPushButton, QScrollArea, QSizePolicy, QSplitter,
                                   QStackedWidget, QStyle, QStyledItemDelegate, QVBoxLayout,
                                   QWidget)

    from . import theme
except ImportError:  # pragma: no cover - reported by main()
    QApplication = None

from .. import paths
from ..totp import generate as totp_generate
from . import model
from .widgets import Card, Row, Switch, icon, pill, repolish, rounded

APP_ID = "icp-gui"
CLIPBOARD_CLEAR_SECONDS = 30
_ITEM_ROLE = Qt.UserRole + 1 if QApplication else 0
_SUBTITLE_ROLE = Qt.UserRole + 2 if QApplication else 0
_KEY_ROLE = Qt.UserRole + 3 if QApplication else 0
_COUNT_ROLE = Qt.UserRole + 4 if QApplication else 0

_SECTION_ICONS = {"all": ("dialog-password", "lock"), "codes": ("clock", "chronometer"),
                  "shared": ("system-users", "user-group-new"),
                  "wifi": ("network-wireless", "network-wireless-symbolic"),
                  "hme": ("mail-message", "mail-unread")}


class _SidebarDelegate(QStyledItemDelegate):
    """Sidebar sections: icon, name and a dimmed count, on a rounded selection."""

    def __init__(self, window):
        super().__init__(window)
        self._w = window

    def sizeHint(self, option, index):
        return QSize(option.rect.width(), 34)

    def paint(self, painter, option, index):
        t = self._w.t
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        rect = QRectF(option.rect).adjusted(2, 1, -2, -1)
        selected = bool(option.state & QStyle.State_Selected)
        if selected:
            rounded(painter, rect, QColor(t["accent"]))
        elif option.state & QStyle.State_MouseOver:
            hover = QColor(t["text"])
            hover.setAlpha(16)
            rounded(painter, rect, hover)
        fg = QColor(t["accent_text"] if selected else t["text"])
        icon = index.data(Qt.DecorationRole)
        x = rect.left() + 10
        if icon and not icon.isNull():
            icon.paint(painter, int(x), int(rect.center().y() - 9), 18, 18)
        x += 28
        count = str(index.data(_COUNT_ROLE) or "")
        fm = option.fontMetrics
        cw = fm.horizontalAdvance(count) + 4
        painter.setPen(fg)
        painter.drawText(QRectF(x, rect.top(), rect.right() - x - cw - 10, rect.height()),
                         Qt.AlignLeft | Qt.AlignVCenter, index.data(Qt.DisplayRole) or "")
        painter.setPen(QColor(t["accent_text"] if selected else t["dim"]))
        painter.drawText(QRectF(rect.right() - cw - 10, rect.top(), cw, rect.height()),
                         Qt.AlignRight | Qt.AlignVCenter, count)
        painter.restore()


class _EntryDelegate(QStyledItemDelegate):
    """List rows: monogram avatar, bold title and a dimmed account line."""

    def __init__(self, window):
        super().__init__(window)
        self._w = window

    def sizeHint(self, option, index):
        return QSize(option.rect.width(), 54)

    def paint(self, painter, option, index):
        t = self._w.t
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        rect = QRectF(option.rect).adjusted(2, 1, -2, -1)
        selected = bool(option.state & QStyle.State_Selected)
        if selected:
            rounded(painter, rect, QColor(t["accent"]))
        title = index.data(Qt.DisplayRole) or ""
        theme.paint_avatar(painter, QRectF(rect.left() + 10, rect.center().y() - 16, 32, 32),
                           title, index.data(_KEY_ROLE) or title)
        x = rect.left() + 54
        width = rect.right() - x - 8
        fm = option.fontMetrics
        bold = QFont(option.font)
        bold.setBold(True)
        painter.setFont(bold)
        painter.setPen(QColor(t["accent_text"] if selected else t["text"]))
        top = QRectF(x, rect.top() + 7, width, rect.height() / 2 - 7)
        painter.drawText(top, Qt.AlignLeft | Qt.AlignVCenter,
                         fm.elidedText(title, Qt.ElideRight, int(width) - 8))
        painter.setFont(option.font)
        sub_color = QColor(t["accent_text"])
        sub_color.setAlphaF(0.8)
        painter.setPen(sub_color if selected else QColor(t["dim"]))
        bottom = QRectF(x, rect.center().y(), width, rect.height() / 2 - 7)
        painter.drawText(bottom, Qt.AlignLeft | Qt.AlignVCenter,
                         fm.elidedText(index.data(_SUBTITLE_ROLE) or "", Qt.ElideRight, int(width)))
        painter.restore()


class _Ring(QWidget):
    """Countdown ring for a one-time code: the arc empties as the code nears expiry."""

    def __init__(self, window):
        super().__init__()
        self._w, self._left, self._period = window, 0, 30
        self.setFixedSize(22, 22)

    def set(self, left: int, period: int) -> None:
        self._left, self._period = left, max(1, period)
        self.update()

    def paintEvent(self, _):
        t = self._w.t
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(3, 3, 16, 16)
        p.setPen(QPen(QColor(t["border"]), 3))
        p.drawEllipse(r)
        pen = QPen(QColor(t["warn"] if self._left <= 5 else t["accent"]), 3)
        pen.setCapStyle(Qt.RoundCap)
        p.setPen(pen)
        p.drawArc(r, 90 * 16, int(-360 * 16 * self._left / self._period))


class _Header(QWidget):
    """Detail header: big monogram, title and a dimmed (or linked) subtitle."""

    def __init__(self):
        super().__init__()
        lay = QHBoxLayout(self)
        lay.setContentsMargins(4, 0, 0, 0)
        lay.setSpacing(16)
        self.avatar = QLabel(fixedSize=QSize(64, 64))
        lay.addWidget(self.avatar)
        col = QVBoxLayout()
        col.setSpacing(2)
        col.addStretch(1)
        self.title = QLabel(objectName="detailTitle", textFormat=Qt.PlainText, wordWrap=True)
        self.sub = QLabel(objectName="detailSub", openExternalLinks=True)
        col.addWidget(self.title)
        col.addWidget(self.sub)
        col.addStretch(1)
        lay.addLayout(col, 1)

    def set(self, title: str, key: str, sub_html: str) -> None:
        self.avatar.setPixmap(theme.avatar_pixmap(title, key, 64, self.devicePixelRatioF()))
        self.title.setText(title)
        self.sub.setText(sub_html)
        self.sub.setVisible(bool(sub_html))


def _scroll_page(content: "QWidget") -> "QScrollArea":
    """Centre a detail page at a readable width inside a scroll area."""
    content.setMaximumWidth(680)
    holder = QWidget(objectName="detailPane")
    h = QHBoxLayout(holder)
    h.setContentsMargins(32, 28, 32, 28)
    h.addStretch(1)
    h.addWidget(content, 100)
    h.addStretch(1)
    area = QScrollArea(objectName="detailScroll", widgetResizable=True, frameShape=QFrame.NoFrame)
    area.setWidget(holder)
    return area


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


class CredentialView(QWidget):
    MASK = "•" * 12

    def __init__(self, window):
        super().__init__()
        self._w, self._cred = window, None
        col = QVBoxLayout(self)
        col.setContentsMargins(0, 0, 0, 0)
        col.setSpacing(18)
        self.header = _Header()
        col.addWidget(self.header)

        self.card = Card()
        self.user = self.card.add(Row("User name", self.copy_username, "Click to copy"))
        self.user.add(pill("Copy", "Copy user name (Ctrl+B)")).clicked.connect(self.copy_username)

        self.password = self.card.add(Row("Password", self.copy_password, "Click to copy",
                                           mono=True))
        self.reveal = self.password.add(pill("Show", "Show or hide the password",
                                              checkable=True))
        self.reveal.toggled.connect(self._set_revealed)
        self.password.add(pill("Copy", "Copy password (Ctrl+C)", accent=True)
                          ).clicked.connect(self.copy_password)

        self.code = self.card.add(Row("Verification code", self.copy_code, "Click to copy",
                                       mono=True))
        self.ring = self.code.add(_Ring(window))
        self.code.add(pill("Copy", "Copy verification code (Ctrl+T)")).clicked.connect(self.copy_code)

        self.site = self.card.add(Row("Website", self.open_site, "Open in your browser"))
        self.site.add(pill("Open", "Open in your browser")).clicked.connect(self.open_site)
        col.addWidget(self.card)

        self.meta = Card()
        self.group = self.meta.add(Row("Shared group"))
        self.modified = self.meta.add(Row("Last modified"))
        col.addWidget(self.meta)

        self.notes_card = Card()
        self.notes = self.notes_card.add(Row("Notes", wrap=True))
        col.addWidget(self.notes_card)

        self.hint = QLabel(objectName="hint", wordWrap=True)
        col.addWidget(self.hint)
        self.set_clear_seconds(window.clipboard_seconds)
        col.addStretch(1)

    def set_clear_seconds(self, seconds: int) -> None:
        self.hint.setText("Click a field to copy it." + (
            f" Copied passwords and codes are cleared from the clipboard after {seconds} seconds."
            if seconds else ""))

    def show_credential(self, c) -> None:
        self._cred = c
        site = model.website(c)
        url = site if "://" in site else f"https://{site}"
        self.header.set(model.title(c), c.domain or model.title(c),
                        f'<a href="{_esc(url)}">{_esc(site)}</a>' if site
                        else _esc(model.subtitle(c)))
        self.user.value.setText(c.username)
        self.reveal.setChecked(False)
        self._set_revealed(False)
        self.site.value.setText(site)
        self.card.show_rows({self.user: bool(c.username), self.code: bool(c.totp),
                             self.site: bool(site), self.password: bool(c.password)})
        self.group.value.setText(c.group)
        self.modified.value.setText(
            time.strftime("%-d %B %Y at %H:%M", time.localtime(c.mdat)) if c.mdat else "")
        self.meta.show_rows({self.group: bool(c.group), self.modified: bool(c.mdat)})
        self.notes.value.setText(c.notes)
        self.notes_card.show_rows({self.notes: bool(c.notes)})
        self.tick()

    def tick(self) -> None:
        """Refresh the one-time code and its countdown (called every second)."""
        if not self._cred or not self._cred.totp:
            return
        code = totp_generate(self._cred.totp)
        if not code:
            self.code.value.setText("unavailable")
            return
        digits, half = code["code"], len(code["code"]) // 2
        left = max(0, int(code["expires"] - time.time()))
        self.code.value.setText(f"{digits[:half]} {digits[half:]}")
        self.ring.set(left, code["period"])
        self.ring.setToolTip(f"Changes in {left} s")

    def _set_revealed(self, on: bool) -> None:
        # A fixed-length mask, so a hidden password doesn't give away its length.
        self.password.value.setText(self._cred.password if on and self._cred else self.MASK)
        self.reveal.setText("Hide" if on else "Show")

    def open_site(self) -> None:
        site = model.website(self._cred) if self._cred else ""
        if site:
            QDesktopServices.openUrl(QUrl(site if "://" in site else f"https://{site}"))

    def copy_username(self) -> None:
        if self._cred and self._cred.username:
            self._w.copy(self._cred.username, "User name", secret=False)
            self.user.flash()

    def copy_password(self) -> None:
        if self._cred and self._cred.password:
            self._w.copy(self._cred.password, "Password")
            self.password.flash()

    def copy_code(self) -> None:
        code = totp_generate(self._cred.totp) if self._cred else {}
        if code:
            self._w.copy(code["code"], "Verification code")
            self.code.flash()


class AliasView(QWidget):
    def __init__(self, window):
        super().__init__()
        self._w, self._alias = window, None
        col = QVBoxLayout(self)
        col.setContentsMargins(0, 0, 0, 0)
        col.setSpacing(18)
        self.header = _Header()
        col.addWidget(self.header)
        self.card = Card()
        self.address = self.card.add(Row("Address", self.copy_address, "Click to copy"))
        self.address.add(pill("Copy", "Copy address (Ctrl+C)", accent=True)
                         ).clicked.connect(self.copy_address)
        self.forward = self.card.add(Row("Forwards to"))
        self.state = self.card.add(Row("Status"))
        self.domain = self.card.add(Row("Created for"))
        col.addWidget(self.card)
        self.note_card = Card()
        self.note = self.note_card.add(Row("Note", wrap=True))
        col.addWidget(self.note_card)
        col.addStretch(1)

    def show_alias(self, a) -> None:
        self._alias = a
        self.header.set(a.label or a.address, a.address, "Hide My Email")
        self.address.value.setText(a.address)
        self.forward.value.setText(a.forward_to)
        self.state.value.setText("Active" if a.is_active else "Inactive")
        self.domain.value.setText(a.domain)
        self.card.show_rows({self.forward: bool(a.forward_to), self.domain: bool(a.domain)})
        self.note.value.setText(a.note)
        self.note_card.show_rows({self.note: bool(a.note)})

    def copy_address(self) -> None:
        if self._alias:
            self._w.copy(self._alias.address, "Address", secret=False)
            self.address.flash()


class _Toast(QLabel):
    """A short message floating at the bottom of the window."""

    def __init__(self, parent):
        super().__init__(parent, objectName="toast")
        self.hide()
        self._timer = QTimer(self, singleShot=True, timeout=self.hide)

    def show_message(self, text: str, ms: int = 2200) -> None:
        self.setText(text)
        self.adjustSize()
        p = self.parentWidget()
        self.move((p.width() - self.width()) // 2, p.height() - self.height() - 24)
        self.raise_()
        self.show()
        self._timer.start(ms)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.prefs = QSettings("icp", APP_ID)
        self.theme_mode = str(self.prefs.value("theme", "auto"))
        if self.theme_mode not in theme.MODES:
            self.theme_mode = "auto"
        self.clipboard_seconds = int(self.prefs.value("clipboard_seconds",
                                                      CLIPBOARD_CLEAR_SECONDS))
        self.anisette_url = str(self.prefs.value("anisette_url", "")
                                or os.environ.get("ICP_ANISETTE_URL", ""))
        self.t = theme.apply(QApplication.instance(), self.theme_mode)
        self.setWindowTitle("iCloud Passwords")
        self.setWindowIcon(icon("dialog-password", "password-manager", "keepassxc"))
        self.creds, self.aliases, self._vault_mtime = [], [], None
        self._clip_text, self._sync = None, None

        # --- sidebar: title, sections, sync status ---
        side = QWidget(objectName="sidebarPane")
        side.setMinimumWidth(190)
        sl = QVBoxLayout(side)
        sl.setContentsMargins(10, 18, 10, 12)
        sl.setSpacing(10)
        sl.addWidget(QLabel("Passwords", objectName="appTitle"))
        self.sections = QListWidget()
        self.sections.setItemDelegate(_SidebarDelegate(self))
        self.sections.setMouseTracking(True)
        for key, label in model.SECTIONS:
            item = QListWidgetItem(icon(*_SECTION_ICONS[key]), label)
            item.setData(_ITEM_ROLE, key)
            self.sections.addItem(item)
        self.sections.currentRowChanged.connect(lambda _: self.show_passwords())
        self.sections.itemPressed.connect(lambda _: self.show_passwords())
        sl.addWidget(self.sections, 1)
        self.status = QLabel(objectName="syncStatus", wordWrap=True)
        sl.addWidget(self.status)
        self.sync_button = pill("Sync now", "Fetch new and changed passwords from iCloud (Ctrl+R)")
        self.sync_button.setIcon(icon("view-refresh"))
        self.sync_button.clicked.connect(self.start_sync)
        sl.addWidget(self.sync_button)
        self.extension_button = pill("Browser Extension", "Set up autofill in your browsers",
                                     checkable=True)
        self.extension_button.setIcon(icon("internet-web-browser", "applications-internet"))
        self.extension_button.clicked.connect(
            lambda on: self.show_page("extension") if on else self.show_passwords())
        sl.addWidget(self.extension_button)
        self.settings_button = pill("Settings", "Settings and setup checklist", checkable=True)
        self.settings_button.setIcon(icon("configure", "settings", "preferences-system"))
        self.settings_button.clicked.connect(
            lambda on: self.show_page("settings") if on else self.show_passwords())
        sl.addWidget(self.settings_button)

        # --- list: search, heading, entries ---
        middle = QWidget(objectName="listPane")
        middle.setMinimumWidth(260)
        ml = QVBoxLayout(middle)
        ml.setContentsMargins(10, 14, 10, 6)
        ml.setSpacing(10)
        self.search = QLineEdit(objectName="search", placeholderText="Search",
                                clearButtonEnabled=True)
        if not (find := icon("edit-find", "search")).isNull():
            self.search.addAction(find, QLineEdit.LeadingPosition)
        self.search.textChanged.connect(self.refresh_list)
        self.search.returnPressed.connect(self._focus_list)
        ml.addWidget(self.search)
        head = QHBoxLayout()
        self.list_header = QLabel(objectName="listHeader")
        self.list_count = QLabel(objectName="listCount")
        head.addWidget(self.list_header)
        head.addStretch(1)
        head.addWidget(self.list_count)
        ml.addLayout(head)
        self.entries = QListWidget(uniformItemSizes=True)
        self.entries.setItemDelegate(_EntryDelegate(self))
        self.entries.currentItemChanged.connect(self._show_current)
        ml.addWidget(self.entries, 1)

        # --- detail ---
        self.empty = QLabel(objectName="empty", alignment=Qt.AlignCenter, wordWrap=True)
        self.empty.setMargin(40)
        self.cred_view = CredentialView(self)
        self.alias_view = AliasView(self)
        self.cred_page = _scroll_page(self.cred_view)
        self.alias_page = _scroll_page(self.alias_view)
        self.detail = QStackedWidget(objectName="detailPane")
        for w in (self.empty, self.cred_page, self.alias_page):
            self.detail.addWidget(w)

        inner = QSplitter(childrenCollapsible=False)
        inner.addWidget(middle)
        inner.addWidget(self.detail)
        inner.setStretchFactor(1, 1)
        inner.setSizes([330, 560])
        self.inner_splitter = inner
        from .extension_page import ExtensionPage
        from .settings import SettingsPage
        self.settings_page = SettingsPage(self)
        self.settings_scroll = _scroll_page(self.settings_page)
        self.extension_page = ExtensionPage(self)
        self.extension_scroll = _scroll_page(self.extension_page)
        self.content = QStackedWidget()
        self.content.addWidget(inner)
        self.content.addWidget(self.settings_scroll)
        self.content.addWidget(self.extension_scroll)

        split = QSplitter(childrenCollapsible=False)
        split.addWidget(side)
        split.addWidget(self.content)
        split.setStretchFactor(1, 1)
        split.setSizes([220, 890])
        self.splitter = split
        body = QWidget(objectName="main")
        bl = QVBoxLayout(body)
        bl.setContentsMargins(0, 0, 0, 0)
        bl.addWidget(split)
        self.setCentralWidget(body)
        self.toast = _Toast(body)

        # --- shortcuts ---
        for keys, slot in ((QKeySequence.Find, self._focus_search),
                           ("Ctrl+B", lambda: self._view_call("copy_username")),
                           ("Ctrl+T", lambda: self._view_call("copy_code")),
                           ("Ctrl+R", self.start_sync), (QKeySequence.Refresh, self.start_sync),
                           (QKeySequence.Quit, self.close)):
            a = QAction(self, shortcut=QKeySequence(keys))
            a.triggered.connect(slot)
            self.addAction(a)
        # Ctrl+C copies the password only from the list, so text in fields still copies normally.
        copy_secret = QAction(self.entries, shortcut=QKeySequence.Copy,
                              shortcutContext=Qt.WidgetShortcut)
        copy_secret.triggered.connect(self._copy_primary)
        self.entries.addAction(copy_secret)
        self.search.installEventFilter(self)

        try:
            QGuiApplication.styleHints().colorSchemeChanged.connect(self._retheme)
        except AttributeError:  # Qt < 6.5
            pass

        self._restore_layout()
        self.reload()
        self.sections.setCurrentRow(0)
        self._setup_problems = 0
        self._ticker = QTimer(self, interval=1000, timeout=self._tick)
        self._ticker.start()
        QTimer.singleShot(300, self.settings_page.refresh)  # flags setup problems in the sidebar

    # --- pages and preferences ---
    def show_page(self, name: str) -> None:
        """Switch from the password list to the Settings or Browser Extension page."""
        self.settings_button.setChecked(name == "settings")
        self.extension_button.setChecked(name == "extension")
        self.sections.blockSignals(True)
        self.sections.setCurrentRow(-1)
        self.sections.blockSignals(False)
        if name == "settings":
            self.content.setCurrentWidget(self.settings_scroll)
            self.settings_page.refresh()
        else:
            self.content.setCurrentWidget(self.extension_scroll)
            self.extension_page.ensure_scanned()

    def show_settings(self) -> None:
        self.show_page("settings")

    def show_passwords(self) -> None:
        self.settings_button.setChecked(False)
        self.extension_button.setChecked(False)
        if self.sections.currentRow() < 0:
            self.sections.blockSignals(True)
            self.sections.setCurrentRow(0)
            self.sections.blockSignals(False)
        self.content.setCurrentIndex(0)
        self.refresh_list()

    def set_theme_mode(self, mode: str) -> None:
        self.theme_mode = mode
        self.prefs.setValue("theme", mode)
        self._retheme()

    def set_clipboard_seconds(self, seconds: int) -> None:
        self.clipboard_seconds = int(seconds)
        self.prefs.setValue("clipboard_seconds", self.clipboard_seconds)
        self.cred_view.set_clear_seconds(self.clipboard_seconds)

    def set_anisette_url(self, url: str) -> None:
        self.anisette_url = url
        self.prefs.setValue("anisette_url", url)

    def set_setup_state(self, problems: int) -> None:
        self._setup_problems = problems
        self._update_status()

    def _retheme(self, *_):
        self.t = theme.apply(QApplication.instance(), self.theme_mode)
        for w in (self.sections, self.entries):
            w.viewport().update()
        self.update()
        self._show_current()

    # --- data ---
    def reload(self) -> None:
        from ..hme.store import load_aliases
        from ..vault.store import load_vault

        vault = paths.vault_file()
        self._vault_mtime = vault.stat().st_mtime if vault.exists() else None
        try:
            self.creds = load_vault().all()
        except Exception as e:  # noqa: BLE001 - keyring locked/unavailable: say so, don't crash
            self.creds = []
            QMessageBox.critical(self, "Could not open the vault",
                                 f"The password vault could not be decrypted:\n\n{e}\n\n"
                                 "Make sure your login keyring is unlocked.")
        try:
            self.aliases = load_aliases()
        except Exception:  # noqa: BLE001 - the alias cache is optional
            self.aliases = []
        counts = model.section_counts(self.creds, self.aliases)
        for row in range(self.sections.count()):
            item = self.sections.item(row)
            key = item.data(_ITEM_ROLE)
            item.setData(_COUNT_ROLE, counts[key])
            item.setHidden(key in ("shared", "codes") and not counts[key])
        self.refresh_list()
        self._update_status()

    def _section(self) -> str:
        item = self.sections.currentItem()
        return item.data(_ITEM_ROLE) if item else "all"

    def refresh_list(self) -> None:
        section, query = self._section(), self.search.text()
        previous = self.entries.currentItem()
        keep = previous.data(_ITEM_ROLE) if previous else None
        self.entries.blockSignals(True)
        self.entries.clear()
        if section == "hme":
            rows = [(a.label or a.address, a.address if a.is_active else f"{a.address} (inactive)",
                     a.address, a) for a in model.aliases_for(self.aliases, query)]
        else:
            rows = [(model.title(c), model.subtitle(c), c.domain, c)
                    for c in model.credentials_for(self.creds, section, query)]
        select = 0
        for i, (title, sub, key, obj) in enumerate(rows):
            item = QListWidgetItem(title)
            item.setData(_SUBTITLE_ROLE, sub)
            item.setData(_KEY_ROLE, key)
            item.setData(_ITEM_ROLE, obj)
            self.entries.addItem(item)
            if obj is keep:
                select = i
        self.entries.blockSignals(False)
        self.list_header.setText(dict(model.SECTIONS)[section])
        self.list_count.setText(str(len(rows)))
        if rows:
            self.entries.setCurrentRow(select)
        else:
            self._show_empty(section, query)
        self._show_current()

    def _show_empty(self, section: str, query: str) -> None:
        if query:
            msg = f"No results for “{query}”"
        elif not paths.session_file().exists():
            msg = "Not signed in\n\nRun  icp login  in a terminal, then come back."
        elif section == "hme":
            msg = ("No Hide My Email addresses yet\n\n"
                   "They're fetched by  icp sync  (at most once a day) or  icp show.")
        elif not self.creds:
            msg = "No passwords yet\n\nClick Sync now, or run  icp sync  in a terminal."
        else:
            msg = "Nothing here"
        self.empty.setText(msg)

    def _show_current(self, *_) -> None:
        item = self.entries.currentItem()
        obj = item.data(_ITEM_ROLE) if item else None
        if obj is None:
            self.detail.setCurrentWidget(self.empty)
        elif self._section() == "hme":
            self.alias_view.show_alias(obj)
            self.detail.setCurrentWidget(self.alias_page)
        else:
            self.cred_view.show_credential(obj)
            self.detail.setCurrentWidget(self.cred_page)

    def _tick(self) -> None:
        if self.detail.currentWidget() is self.cred_page:
            self.cred_view.tick()
        if int(time.time()) % 5 == 0:
            vault = paths.vault_file()
            mtime = vault.stat().st_mtime if vault.exists() else None
            if mtime != self._vault_mtime and self._sync is None:
                self.reload()  # a sync from the browser helper or a terminal landed
            else:
                self._update_status()

    def _update_status(self) -> None:
        if self._sync is not None:
            return
        text, problem = model.sync_status()
        if getattr(self, "_setup_problems", 0) and not problem:
            n = self._setup_problems
            text, problem = f"Setup: {n} problem{'s' if n > 1 else ''} - see Settings", True
        self.status.setText(text)
        self.status.setProperty("problem", problem)
        repolish(self.status)

    # --- sync ---
    def start_sync(self) -> None:
        if self._sync is not None:
            return
        proc = QProcess(self)
        proc.setProgram(sys.executable)
        proc.setArguments(["-m", "icp", "sync"])
        if self.anisette_url:
            env = QProcessEnvironment.systemEnvironment()
            env.insert("ICP_ANISETTE_URL", self.anisette_url)
            proc.setProcessEnvironment(env)
        proc.finished.connect(self._sync_finished)
        proc.errorOccurred.connect(lambda _: self._sync_finished(-1, None))
        self._sync = proc
        self.sync_button.setEnabled(False)
        self.sync_button.setText("Syncing…")
        self.status.setText("Syncing with iCloud…")
        proc.start()

    def _sync_finished(self, code, _status) -> None:
        proc, self._sync = self._sync, None
        if proc is None:
            return
        out = bytes(proc.readAllStandardOutput()).decode(errors="replace").strip()
        err = bytes(proc.readAllStandardError()).decode(errors="replace").strip()
        proc.deleteLater()
        self.sync_button.setEnabled(True)
        self.sync_button.setText("Sync now")
        self.reload()
        last = (err.splitlines() or [""])[-1].removeprefix("error: ")
        if code == 0:
            self.toast.show_message(out.splitlines()[0] if out else "Synced", 4000)
        elif code == 75:  # EXIT_SKIPPED: paced, busy or waiting for a login
            self.toast.show_message(f"Sync {last}" if last else "Sync skipped", 5000)
        else:
            QMessageBox.warning(self, "Sync failed", last or "The sync did not complete.")

    # --- clipboard ---
    def copy(self, text: str, what: str, secret: bool = True) -> None:
        """Copy to the clipboard. Secrets are marked so KDE's clipboard history skips them,
        and cleared after CLIPBOARD_CLEAR_SECONDS if nothing else was copied meanwhile."""
        data = QMimeData()
        data.setText(text)
        if secret:
            data.setData("x-kde-passwordManagerHint", b"secret")
        QGuiApplication.clipboard().setMimeData(data)
        secs = self.clipboard_seconds
        if secret and secs:
            self._clip_text = text
            QTimer.singleShot(secs * 1000, lambda t=text: self._clear_clip(t))
            self.toast.show_message(f"{what} copied · clears in {secs} s")
        else:
            self.toast.show_message(f"{what} copied")

    def _clear_clip(self, text: str) -> None:
        clip = QGuiApplication.clipboard()
        if self._clip_text == text and clip.text() == text:
            clip.clear()
        if self._clip_text == text:
            self._clip_text = None

    # --- keyboard ---
    def _focus_search(self) -> None:
        self.search.setFocus()
        self.search.selectAll()

    def _focus_list(self) -> None:
        if self.entries.count():
            self.entries.setFocus()

    def _view_call(self, name: str) -> None:
        page = self.detail.currentWidget()
        view = {self.cred_page: self.cred_view, self.alias_page: self.alias_view}.get(page)
        if view is not None and hasattr(view, name):
            getattr(view, name)()

    def _copy_primary(self) -> None:
        if self.detail.currentWidget() is self.alias_page:
            self.alias_view.copy_address()
        else:
            self.cred_view.copy_password()

    def eventFilter(self, obj, event):
        # Up/Down in the search box move through the results without leaving it.
        if obj is self.search and event.type() == event.Type.KeyPress:
            if event.key() in (Qt.Key_Down, Qt.Key_Up) and self.entries.count():
                step = 1 if event.key() == Qt.Key_Down else -1
                row = max(0, min(self.entries.count() - 1, self.entries.currentRow() + step))
                self.entries.setCurrentRow(row)
                return True
            if event.key() == Qt.Key_Escape and self.search.text():
                self.search.clear()
                return True
        return super().eventFilter(obj, event)

    # --- window state ---
    def _restore_layout(self) -> None:
        s = QSettings("icp", APP_ID)
        if s.value("geometry"):
            self.restoreGeometry(s.value("geometry"))
        else:
            self.resize(1120, 700)
        if s.value("sidebar_split"):
            self.splitter.restoreState(s.value("sidebar_split"))
        if s.value("list_split"):
            self.inner_splitter.restoreState(s.value("list_split"))

    def closeEvent(self, event) -> None:
        s = QSettings("icp", APP_ID)
        s.setValue("geometry", self.saveGeometry())
        s.setValue("sidebar_split", self.splitter.saveState())
        s.setValue("list_split", self.inner_splitter.saveState())
        self.settings_page.stop()
        if self._clip_text is not None:  # don't leave a copied password behind
            self._clear_clip(self._clip_text)
        super().closeEvent(event)


def main(argv=None) -> int:
    if QApplication is None:
        print("error: the desktop app needs PySide6 - install it with: "
              "pip install -e '.[gui]'", file=sys.stderr)
        return 1
    app = QApplication(sys.argv if argv is None else argv)
    app.setApplicationName("iCloud Passwords")
    app.setDesktopFileName(APP_ID)  # lets Wayland compositors match the .desktop entry/icon
    window = MainWindow()
    if "--minimized" in app.arguments():  # from the login autostart entry
        window.showMinimized()
    else:
        window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
