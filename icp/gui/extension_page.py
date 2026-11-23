"""Browser Extension page: find installed browsers, show whether autofill is connected in
each, and set it up for the selected ones."""

from __future__ import annotations

import subprocess

from PySide6.QtCore import QTimer, QUrl, Qt
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import (QCheckBox, QFrame, QHBoxLayout, QLabel, QMessageBox, QVBoxLayout,
                               QWidget)

from . import browsers, theme
from .browsers import CHROMIUM, FLATPAK
from .widgets import Card, Row, pill, repolish


def _chip(text: str, state: str) -> QLabel:
    chip = QLabel(text, objectName="chip")
    chip.setProperty("state", state)
    return chip


class _BrowserRow(QFrame):
    def __init__(self, inst: browsers.Install, st: browsers.Status, page: "ExtensionPage"):
        super().__init__(objectName="row")
        self.inst, self.st = inst, st
        ready = st.extension == "installed" and st.host and st.sandbox_ok
        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(12)

        self.pick = QCheckBox(cursor=Qt.PointingHandCursor, toolTip="Include in Install")
        self.pick.setChecked(not ready and bool(inst.launch))
        self.pick.setEnabled(bool(inst.launch) or inst.spec.family == CHROMIUM)
        lay.addWidget(self.pick, 0, Qt.AlignTop)
        avatar = QLabel()
        avatar.setPixmap(theme.avatar_pixmap(inst.spec.name, inst.spec.key, 36,
                                             self.devicePixelRatioF()))
        lay.addWidget(avatar, 0, Qt.AlignTop)

        col = QVBoxLayout()
        col.setSpacing(5)
        col.addWidget(QLabel(inst.label, objectName="checkTitle"))
        where = " ".join(inst.launch) if inst.launch else "profile found, program not on PATH"
        col.addWidget(QLabel(where, objectName="checkDetail", textFormat=Qt.PlainText))
        chips = QHBoxLayout()
        chips.setSpacing(6)
        chips.addWidget({"installed": _chip("✓ Extension added", "ok"),
                         "disabled": _chip("! Extension turned off", "warn"),
                         "missing": _chip("✕ Extension not added", "fail")}[st.extension])
        chips.addWidget(_chip("✓ Connected to icp", "ok") if st.host
                        else _chip("✕ Not connected to icp", "fail"))
        if inst.kind == FLATPAK:
            chips.addWidget(_chip("✓ Sandbox allows icp", "ok") if st.sandbox_ok
                            else _chip("✕ Sandbox blocks icp", "fail"))
        chips.addStretch(1)
        col.addLayout(chips)
        step = QLabel(browsers.next_step(inst, st), objectName="checkDetail", wordWrap=True,
                      textInteractionFlags=Qt.TextSelectableByMouse)
        col.addWidget(step)
        if inst.kind == FLATPAK and not st.sandbox_ok:
            cmd = QLabel(browsers.flatpak_permission_command(inst), objectName="command",
                         textInteractionFlags=Qt.TextSelectableByMouse)
            col.addWidget(cmd)
        lay.addLayout(col, 1)

        buttons = QVBoxLayout()
        buttons.setSpacing(6)
        if inst.launch and not ready:
            b = pill("Open extensions" if inst.spec.family == CHROMIUM or not st.unsigned_ok
                     else "Install add-on", "Open the place to add the extension in this browser")
            b.clicked.connect(lambda: page.open_page(self))
            buttons.addWidget(b)
        if inst.kind == FLATPAK and not st.sandbox_ok:
            b = pill("Allow…", "Let this Flatpak browser start icp", accent=True)
            b.clicked.connect(lambda: page.allow_flatpak(inst))
            buttons.addWidget(b)
            b = pill("Copy command", "Copy the flatpak override command")
            b.clicked.connect(lambda: page.copy(browsers.flatpak_permission_command(inst),
                                                "Command"))
            buttons.addWidget(b)
        buttons.addStretch(1)
        lay.addLayout(buttons)


class ExtensionPage(QWidget):
    def __init__(self, window):
        super().__init__()
        self._w = window
        self._rows: list[_BrowserRow] = []
        col = QVBoxLayout(self)
        col.setContentsMargins(0, 0, 0, 0)
        col.setSpacing(10)
        col.addWidget(QLabel("Browser Extension", objectName="pageTitle"))
        col.addWidget(QLabel("Autofill your iCloud passwords on websites. The extension talks to "
                             "icp on this computer; nothing is sent anywhere else.",
                             objectName="checkDetail", wordWrap=True))
        col.addSpacing(6)

        bar = QHBoxLayout()
        self.scan_btn = pill("Scan for browsers", "Look for installed browsers again")
        self.scan_btn.clicked.connect(self.scan)
        self.install_btn = pill("Install for selected", "Connect icp and open each selected "
                                "browser where the extension is added", accent=True)
        self.install_btn.clicked.connect(self.install_selected)
        bar.addWidget(self.scan_btn)
        bar.addStretch(1)
        bar.addWidget(self.install_btn)
        col.addLayout(bar)
        self.summary = QLabel(objectName="summary")
        col.addWidget(self.summary)
        self.card = Card()
        col.addWidget(self.card)
        self.none = QLabel("No supported browsers found. Supported: " +
                           ", ".join(s.name for s in browsers.SPECS) + ".",
                           objectName="checkDetail", wordWrap=True)
        col.addWidget(self.none)
        col.addSpacing(14)

        col.addWidget(QLabel("MANUAL SETUP", objectName="sectionTitle"))
        manual = Card()
        folder = manual.add(Row("Extension folder", lambda: self.copy(str(browsers.EXTENSION_DIR),
                                                                       "Folder path"),
                                "Click to copy"))
        folder.value.setText(str(browsers.EXTENSION_DIR))
        b = pill("Open", "Open the folder")
        b.clicked.connect(lambda: QDesktopServices.openUrl(
            QUrl.fromLocalFile(str(browsers.EXTENSION_DIR))))
        folder.add(b)
        cid = browsers.predicted_chromium_id()
        ident = manual.add(Row("Chromium extension ID (when loaded from this folder)",
                               lambda: self.copy(cid, "Extension ID"), "Click to copy",
                               mono=True))
        ident.value.setText(cid)
        cmd = browsers.manual_command(cid)
        manual_row = manual.add(Row("Connect icp by hand (Chromium-family and Firefox)",
                                    lambda: self.copy(cmd, "Command"), "Click to copy",
                                    mono=True, wrap=True))
        manual_row.value.setText(cmd)
        for r in (folder, ident, manual_row):
            r.add(pill("Copy", "Copy")).clicked.connect(r._on_click)
        manual.show_rows({})
        col.addWidget(manual)
        col.addStretch(1)
        self._scanned = False

    # --- scanning ---
    def ensure_scanned(self) -> None:
        if not self._scanned:
            self.scan()

    def scan(self) -> None:
        self._scanned = True
        self.card.clear()
        self._rows = []
        installs = browsers.scan()
        ready = 0
        for inst in installs:
            st = browsers.status(inst)
            ready += st.extension == "installed" and st.host and st.sandbox_ok
            row = _BrowserRow(inst, st, self)
            self._rows.append(row)
            self.card.add(row)
        self.card.show_rows({})
        self.none.setVisible(not installs)
        if not installs:
            text, state = "No browsers found", "warn"
        elif ready == len(installs):
            text, state = f"Autofill is set up in all {len(installs)} browsers", "ok"
        elif ready:
            text, state = f"Set up in {ready} of {len(installs)} browsers", "warn"
        else:
            text, state = f"Found {len(installs)} browsers - not set up in any yet", "fail"
        self.summary.setText(text)
        self.summary.setProperty("state", state)
        repolish(self.summary)
        self.install_btn.setEnabled(any(r.pick.isEnabled() for r in self._rows))

    # --- actions ---
    def install_selected(self) -> None:
        picked = [r for r in self._rows if r.pick.isChecked()]
        if not picked:
            self._w.toast.show_message("Tick the browsers to set up first")
            return
        notes, opened = [], 0
        for r in picked:
            inst, st = r.inst, r.st
            try:
                # A real ID (extension already loaded) beats the predicted one.
                browsers.register_host(inst, self._w.anisette_url,
                                       st.ext_id if inst.spec.family == CHROMIUM else "")
            except OSError as e:
                notes.append(f"{inst.label}: couldn't connect icp ({e})")
                continue
            if inst.kind == FLATPAK and not st.sandbox_ok:
                notes.append(f"{inst.label}: also needs sandbox access (Allow…)")
            if st.extension != "installed" and inst.launch:
                if self._open(r):
                    opened += 1
        msg = f"Connected icp in {len(picked)} browser{'s' if len(picked) > 1 else ''}"
        if opened:
            msg += f" · opened {opened} to add the extension"
        self._w.toast.show_message(msg, 5000)
        if notes:
            QMessageBox.information(self, "Almost done", "\n".join(notes))
        self.scan()

    def _open(self, row: _BrowserRow) -> bool:
        inst, st = row.inst, row.st
        argv = browsers.extensions_page_argv(inst, st)
        if not argv:
            return False
        ok, err = browsers.launch(argv)
        if not ok:
            self._w.toast.show_message(f"Couldn't open {inst.label}: {err}", 5000)
            return False
        # Have the path ready for the file picker that comes next.
        if inst.spec.family == CHROMIUM:
            QGuiApplication.clipboard().setText(str(browsers.EXTENSION_DIR))
        elif not st.unsigned_ok:
            QGuiApplication.clipboard().setText(str(browsers.EXTENSION_DIR / "manifest.json"))
        return True

    def open_page(self, row: _BrowserRow) -> None:
        if self._open(row):
            hint = ("folder path copied - paste it in the Load unpacked dialog"
                    if row.inst.spec.family == CHROMIUM else
                    "click Add in the prompt" if row.st.unsigned_ok else
                    "manifest path copied - paste it in the file dialog")
            self._w.toast.show_message(f"Opened {row.inst.label} · {hint}", 5000)
        QTimer.singleShot(8000, self.scan)

    def allow_flatpak(self, inst: browsers.Install) -> None:
        answer = QMessageBox.question(
            self, f"Allow {inst.label} to start icp?",
            f"Autofill in a Flatpak browser needs permission to start programs outside its "
            f"sandbox (it runs icp through flatpak-spawn). This weakens the sandbox for "
            f"{inst.spec.name}: any page that compromised the browser could do the same.\n\n"
            f"This runs:\n{browsers.flatpak_permission_command(inst)}\n\n"
            f"You can undo it with:\nflatpak override --user --reset {inst.spec.flatpak}")
        if answer != QMessageBox.Yes:
            return
        try:
            p = subprocess.run(browsers.flatpak_permission_command(inst).split(),
                               capture_output=True, text=True, timeout=20)
            ok, err = p.returncode == 0, (p.stderr or p.stdout).strip()
        except (OSError, subprocess.SubprocessError) as e:
            ok, err = False, str(e)
        self._w.toast.show_message(
            f"{inst.label} can now start icp - restart the browser" if ok
            else f"Failed: {err}", 5000)
        self.scan()

    def copy(self, text: str, what: str) -> None:
        QGuiApplication.clipboard().setText(text)
        self._w.toast.show_message(f"{what} copied")
