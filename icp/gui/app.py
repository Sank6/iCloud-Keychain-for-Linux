"""Desktop app for browsing the local vault (`icp-gui`). Read-only and offline, like `icp show`:
it reads the same encrypted vault and Hide My Email cache, and `Sync now` runs `icp sync` in a
child process so pacing, locking and backoff stay in one place. Signing in stays in the terminal
(`icp login`) - its passcode step is irreversible after too many wrong tries.

Needs PySide6: pip install -e '.[gui]'"""

from __future__ import annotations

import sys
import time

try:
    from PySide6.QtCore import QMimeData, QProcess, QSettings, QSize, Qt, QTimer, QUrl
    from PySide6.QtGui import (QAction, QDesktopServices, QFont, QFontDatabase, QGuiApplication,
                               QIcon, QKeySequence, QPalette)
    from PySide6.QtWidgets import (QApplication, QFormLayout, QFrame, QHBoxLayout, QLabel,
                                   QLineEdit, QListWidget, QListWidgetItem, QMainWindow,
                                   QMessageBox, QPlainTextEdit, QProgressBar, QPushButton,
                                   QSplitter, QStackedWidget, QStyle, QStyledItemDelegate,
                                   QStyleOptionViewItem, QToolButton, QVBoxLayout, QWidget)
except ImportError:  # pragma: no cover - reported by main()
    QApplication = None

from .. import paths
from ..totp import generate as totp_generate
from . import model

APP_ID = "icp-gui"
CLIPBOARD_CLEAR_SECONDS = 30
_ITEM_ROLE = Qt.UserRole + 1 if QApplication else 0
_SUBTITLE_ROLE = Qt.UserRole + 2 if QApplication else 0


def _icon(*names: str, fallback=None) -> "QIcon":
    for name in names:
        icon = QIcon.fromTheme(name)
        if not icon.isNull():
            return icon
    return QApplication.style().standardIcon(fallback) if fallback is not None else QIcon()


class _TwoLineDelegate(QStyledItemDelegate):
    """List rows with a title line and a dimmed second line (account or address)."""

    def sizeHint(self, option, index):
        fm = option.fontMetrics
        return QSize(option.rect.width(), fm.height() * 2 + 14)

    def paint(self, painter, option, index):
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        opt.text = ""
        style = opt.widget.style() if opt.widget else QApplication.style()
        style.drawControl(QStyle.CE_ItemViewItem, opt, painter, opt.widget)

        selected = bool(opt.state & QStyle.State_Selected)
        group = QPalette.Active if opt.state & QStyle.State_Active else QPalette.Inactive
        pal = opt.palette
        main = pal.color(group, QPalette.HighlightedText if selected else QPalette.Text)
        dim = QPalette.HighlightedText if selected else QPalette.PlaceholderText
        rect = opt.rect.adjusted(10, 6, -10, -6)
        fm = opt.fontMetrics
        top, bottom = rect.adjusted(0, 0, 0, -rect.height() // 2), rect.adjusted(0, rect.height() // 2, 0, 0)

        painter.save()
        bold = QFont(opt.font)
        bold.setBold(True)
        painter.setFont(bold)
        painter.setPen(main)
        painter.drawText(top, Qt.AlignLeft | Qt.AlignVCenter,
                         fm.elidedText(index.data(Qt.DisplayRole) or "", Qt.ElideRight, rect.width()))
        painter.setFont(opt.font)
        painter.setPen(pal.color(group, dim))
        painter.drawText(bottom, Qt.AlignLeft | Qt.AlignVCenter,
                         fm.elidedText(index.data(_SUBTITLE_ROLE) or "", Qt.ElideRight, rect.width()))
        painter.restore()


class _Field(QWidget):
    """One detail row: a read-only value plus optional action buttons."""

    def __init__(self, mono: bool = False):
        super().__init__()
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.value = QLineEdit(readOnly=True, frame=False)
        self.value.setStyleSheet("background: transparent;")
        if mono:
            self.value.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        lay.addWidget(self.value, 1)
        self._lay = lay

    def add_button(self, icon: "QIcon", text: str, tip: str, slot,
                   checkable: bool = False) -> "QToolButton":
        b = QToolButton(icon=icon, text=text, toolTip=tip, autoRaise=True, checkable=checkable)
        # Without an icon theme the button would render empty: show its label instead.
        b.setToolButtonStyle(Qt.ToolButtonTextOnly if icon.isNull() else Qt.ToolButtonIconOnly)
        (b.toggled if checkable else b.clicked).connect(slot)
        self._lay.addWidget(b)
        return b


class CredentialView(QWidget):
    def __init__(self, copy):
        super().__init__()
        self._copy, self._cred = copy, None
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 20, 24, 20)

        self.heading = QLabel(wordWrap=True, textInteractionFlags=Qt.TextSelectableByMouse)
        f = self.heading.font()
        f.setPointSizeF(f.pointSizeF() * 1.6)
        f.setBold(True)
        self.heading.setFont(f)
        outer.addWidget(self.heading)
        self.subheading = QLabel(wordWrap=True)
        self.subheading.setForegroundRole(QPalette.PlaceholderText)
        outer.addWidget(self.subheading)
        outer.addSpacing(12)

        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)
        copy_icon = _icon("edit-copy")

        self.username = _Field()
        self.username.add_button(copy_icon, "Copy", "Copy username (Ctrl+B)", self.copy_username)

        self.password = _Field(mono=True)
        self.reveal = self.password.add_button(_icon("view-visible", "password-show-on"), "Show",
                                               "Show password", self._toggle_reveal, checkable=True)
        self.password.add_button(copy_icon, "Copy", "Copy password (Ctrl+C)", self.copy_password)

        self.code = _Field(mono=True)
        self.code._lay.setStretch(0, 0)
        self.code.value.setFixedWidth(self.code.value.fontMetrics().horizontalAdvance("0" * 16))
        self.code_timer = QProgressBar(textVisible=False, maximumWidth=60, maximumHeight=6)
        self.code._lay.insertWidget(1, self.code_timer)
        self.code.add_button(copy_icon, "Copy", "Copy verification code (Ctrl+T)", self.copy_code)
        self.code._lay.addStretch(1)

        self.site = _Field()
        self.site.add_button(_icon("internet-web-browser", "applications-internet"),
                             "Open", "Open website", self._open_site)

        self.group = _Field()
        self.modified = _Field()
        self.notes = QPlainTextEdit(readOnly=True, maximumHeight=140)

        for label, w in (("Username", self.username), ("Password", self.password),
                         ("Verification code", self.code), ("Website", self.site),
                         ("Shared group", self.group), ("Modified", self.modified),
                         ("Notes", self.notes)):
            form.addRow(label, w)
        self._form = form
        outer.addLayout(form)
        outer.addStretch(1)

    def _set_row_visible(self, widget, visible: bool) -> None:
        self._form.setRowVisible(widget, visible)

    def show_credential(self, c) -> None:
        self._cred = c
        self.heading.setText(model.title(c))
        site = model.website(c)
        self.subheading.setText(site or model.subtitle(c))
        self.username.value.setText(c.username)
        self.reveal.setChecked(False)
        self._toggle_reveal(False)
        self.site.value.setText(site)
        self.group.value.setText(c.group)
        self.notes.setPlainText(c.notes)
        self.modified.value.setText(
            time.strftime("%d %b %Y, %H:%M", time.localtime(c.mdat)) if c.mdat else "")
        self._set_row_visible(self.username, bool(c.username))
        self._set_row_visible(self.code, bool(c.totp))
        self._set_row_visible(self.site, bool(site))
        self._set_row_visible(self.group, bool(c.group))
        self._set_row_visible(self.modified, bool(c.mdat))
        self._set_row_visible(self.notes, bool(c.notes))
        self.tick()

    def tick(self) -> None:
        """Refresh the one-time code and its countdown (called every second)."""
        if not self._cred or not self._cred.totp:
            return
        code = totp_generate(self._cred.totp)
        if not code:
            self.code.value.setText("unavailable")
            return
        digits = code["code"]
        half = len(digits) // 2
        left = max(0, int(code["expires"] - time.time()))
        self.code.value.setText(f"{digits[:half]} {digits[half:]}   ({left}s)")
        self.code_timer.setRange(0, code["period"])
        self.code_timer.setValue(left)

    def _toggle_reveal(self, on: bool) -> None:
        # A fixed-length mask, so a hidden password doesn't give away its length.
        self.password.value.setText(self._cred.password if on and self._cred else "•" * 10)
        self.reveal.setToolTip("Hide password" if on else "Show password")
        self.reveal.setText("Hide" if on else "Show")

    def _open_site(self) -> None:
        site = model.website(self._cred) if self._cred else ""
        if site:
            QDesktopServices.openUrl(QUrl(site if "://" in site else f"https://{site}"))

    def copy_username(self) -> None:
        if self._cred and self._cred.username:
            self._copy(self._cred.username, "Username", secret=False)

    def copy_password(self) -> None:
        if self._cred and self._cred.password:
            self._copy(self._cred.password, "Password")

    def copy_code(self) -> None:
        code = totp_generate(self._cred.totp) if self._cred else {}
        if code:
            self._copy(code["code"], "Verification code")


class AliasView(QWidget):
    def __init__(self, copy):
        super().__init__()
        self._copy, self._alias = copy, None
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 20, 24, 20)
        self.heading = QLabel(wordWrap=True)
        f = self.heading.font()
        f.setPointSizeF(f.pointSizeF() * 1.6)
        f.setBold(True)
        self.heading.setFont(f)
        outer.addWidget(self.heading)
        outer.addSpacing(12)
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)
        self.address = _Field()
        self.address.add_button(_icon("edit-copy"), "Copy", "Copy address (Ctrl+C)",
                                self.copy_address)
        self.forward = _Field()
        self.state = _Field()
        self.domain = _Field()
        self.note = QPlainTextEdit(readOnly=True, maximumHeight=140)
        for label, w in (("Address", self.address), ("Forwards to", self.forward),
                         ("Status", self.state), ("Created for", self.domain), ("Note", self.note)):
            form.addRow(label, w)
        self._form = form
        outer.addLayout(form)
        outer.addStretch(1)

    def show_alias(self, a) -> None:
        self._alias = a
        self.heading.setText(a.label or a.address)
        self.address.value.setText(a.address)
        self.forward.value.setText(a.forward_to)
        self.state.value.setText("Active" if a.is_active else "Inactive")
        self.domain.value.setText(a.domain)
        self.note.setPlainText(a.note)
        self._form.setRowVisible(self.domain, bool(a.domain))
        self._form.setRowVisible(self.note, bool(a.note))

    def copy_address(self) -> None:
        if self._alias:
            self._copy(self._alias.address, "Address", secret=False)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("iCloud Passwords")
        self.setWindowIcon(_icon("dialog-password", "password-manager", "keepassxc",
                                 fallback=QStyle.SP_DialogApplyButton))
        self.creds, self.aliases, self._vault_mtime = [], [], None
        self._clip_text, self._sync = None, None

        # --- top bar: search + sync ---
        self.search = QLineEdit(placeholderText="Search  (Ctrl+F)", clearButtonEnabled=True)
        if not (find := _icon("edit-find")).isNull():
            self.search.addAction(find, QLineEdit.LeadingPosition)
        self.search.textChanged.connect(self.refresh_list)
        self.search.returnPressed.connect(self._focus_list)
        self.sync_button = QPushButton(_icon("view-refresh", fallback=QStyle.SP_BrowserReload),
                                       "Sync now")
        self.sync_button.setToolTip("Fetch new and changed passwords from iCloud (Ctrl+R)")
        self.sync_button.clicked.connect(self.start_sync)
        top = QHBoxLayout()
        top.setContentsMargins(8, 8, 8, 4)
        top.addWidget(self.search, 1)
        top.addWidget(self.sync_button)

        # --- three panes ---
        self.sections = QListWidget(frameShape=QFrame.NoFrame)
        self.sections.setIconSize(QSize(20, 20))
        self.sections.setSpacing(2)
        icons = {"all": ("dialog-password", "lock"), "codes": ("clock", "chronometer"),
                 "shared": ("system-users", "user-group-new"),
                 "wifi": ("network-wireless", "network-wireless-symbolic"),
                 "hme": ("mail-message", "mail-unread")}
        for key, label in model.SECTIONS:
            item = QListWidgetItem(_icon(*icons[key]), label)
            item.setData(_ITEM_ROLE, key)
            self.sections.addItem(item)
        self.sections.currentRowChanged.connect(lambda _: self.refresh_list())

        self.entries = QListWidget(frameShape=QFrame.NoFrame, uniformItemSizes=True)
        self.entries.setItemDelegate(_TwoLineDelegate(self.entries))
        self.entries.currentItemChanged.connect(self._show_current)

        self.empty = QLabel(alignment=Qt.AlignCenter, wordWrap=True)
        self.empty.setForegroundRole(QPalette.PlaceholderText)
        self.cred_view = CredentialView(self.copy)
        self.alias_view = AliasView(self.copy)
        self.detail = QStackedWidget()
        for w in (self.empty, self.cred_view, self.alias_view):
            self.detail.addWidget(w)

        split = QSplitter()
        split.addWidget(self.sections)
        split.addWidget(self.entries)
        split.addWidget(self.detail)
        split.setStretchFactor(2, 1)
        split.setSizes([200, 320, 480])
        self.splitter = split

        body = QWidget()
        lay = QVBoxLayout(body)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addLayout(top)
        lay.addWidget(split, 1)
        self.setCentralWidget(body)

        self.status = QLabel()
        self.statusBar().addWidget(self.status, 1)

        # --- shortcuts ---
        for keys, slot in ((QKeySequence.Find, self._focus_search),
                           ("Ctrl+B", lambda: self._current_view_call("copy_username")),
                           ("Ctrl+T", lambda: self._current_view_call("copy_code")),
                           ("Ctrl+R", self.start_sync), (QKeySequence.Refresh, self.start_sync),
                           (QKeySequence.Quit, self.close)):
            a = QAction(self, shortcut=QKeySequence(keys))
            a.triggered.connect(slot)
            self.addAction(a)
        # Ctrl+C copies the secret only from the list, so it still copies text in the fields.
        copy_secret = QAction(self.entries, shortcut=QKeySequence.Copy,
                              shortcutContext=Qt.WidgetShortcut)
        copy_secret.triggered.connect(self._copy_primary)
        self.entries.addAction(copy_secret)
        self.search.installEventFilter(self)

        self._restore_layout()
        self.reload()
        self.sections.setCurrentRow(0)

        self._ticker = QTimer(self, interval=1000)
        self._ticker.timeout.connect(self._tick)
        self._ticker.start()

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
            label = dict(model.SECTIONS)[key]
            item.setText(f"{label}  ({counts[key]})")
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
            rows = [(a.label or a.address, a.address if a.is_active else f"{a.address} (inactive)", a)
                    for a in model.aliases_for(self.aliases, query)]
        else:
            rows = [(model.title(c), model.subtitle(c), c)
                    for c in model.credentials_for(self.creds, section, query)]
        select = 0
        for i, (title, sub, obj) in enumerate(rows):
            item = QListWidgetItem(title)
            item.setData(_SUBTITLE_ROLE, sub)
            item.setData(_ITEM_ROLE, obj)
            item.setToolTip(f"{title}\n{sub}")
            self.entries.addItem(item)
            if obj is keep:
                select = i
        self.entries.blockSignals(False)
        if rows:
            self.entries.setCurrentRow(select)
        else:
            self._show_empty(section, query)
        self._show_current()

    def _show_empty(self, section: str, query: str) -> None:
        if query:
            msg = f"No results for “{query}”."
        elif not paths.session_file().exists():
            msg = "Not signed in.\n\nRun  icp login  in a terminal, then come back."
        elif section == "hme":
            msg = ("No Hide My Email addresses cached yet.\n\n"
                   "They're fetched during  icp sync  (at most once a day) or by  icp show.")
        elif not self.creds:
            msg = "The vault is empty.\n\nClick Sync now, or run  icp sync  in a terminal."
        else:
            msg = "Nothing here."
        self.empty.setText(msg)

    def _show_current(self, *_) -> None:
        item = self.entries.currentItem()
        obj = item.data(_ITEM_ROLE) if item else None
        if obj is None:
            self.detail.setCurrentWidget(self.empty)
        elif self._section() == "hme":
            self.alias_view.show_alias(obj)
            self.detail.setCurrentWidget(self.alias_view)
        else:
            self.cred_view.show_credential(obj)
            self.detail.setCurrentWidget(self.cred_view)

    def _tick(self) -> None:
        if self.detail.currentWidget() is self.cred_view:
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
        n = sum(model.in_section(c, "all") for c in self.creds)
        self.status.setText(f"{'⚠  ' if problem else ''}{n} passwords  ·  {text}")

    # --- sync ---
    def start_sync(self) -> None:
        if self._sync is not None:
            return
        proc = QProcess(self)
        proc.setProgram(sys.executable)
        proc.setArguments(["-m", "icp", "sync"])
        proc.finished.connect(self._sync_finished)
        proc.errorOccurred.connect(lambda _: self._sync_finished(-1, None))
        self._sync = proc
        self.sync_button.setEnabled(False)
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
        self.reload()
        last = (err.splitlines() or [""])[-1].removeprefix("error: ")
        if code == 0:
            self.statusBar().showMessage(out.splitlines()[0] if out else "Synced.", 8000)
        elif code == 75:  # EXIT_SKIPPED: paced, busy or waiting for a login
            self.statusBar().showMessage(f"Sync {last}" if last else "Sync skipped.", 8000)
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
        if secret:
            self._clip_text = text
            QTimer.singleShot(CLIPBOARD_CLEAR_SECONDS * 1000, lambda t=text: self._clear_clip(t))
            self.statusBar().showMessage(
                f"{what} copied - clears in {CLIPBOARD_CLEAR_SECONDS} seconds", 4000)
        else:
            self.statusBar().showMessage(f"{what} copied", 3000)

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

    def _current_view_call(self, name: str) -> None:
        view = self.detail.currentWidget()
        if hasattr(view, name):
            getattr(view, name)()

    def _copy_primary(self) -> None:
        if self.detail.currentWidget() is self.alias_view:
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
            self.resize(1100, 680)
        if s.value("splitter"):
            self.splitter.restoreState(s.value("splitter"))

    def closeEvent(self, event) -> None:
        s = QSettings("icp", APP_ID)
        s.setValue("geometry", self.saveGeometry())
        s.setValue("splitter", self.splitter.saveState())
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
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
