"""Settings page: appearance, clipboard, startup, the anisette server, account details and a
setup checklist whose items can be fixed with a click or a copied command."""

from __future__ import annotations


from PySide6.QtCore import QThread, QUrl, Qt, Signal
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import (QButtonGroup, QComboBox, QFrame, QHBoxLayout, QLabel, QLineEdit,
                               QPushButton, QVBoxLayout, QWidget)

from .. import paths
from . import setup
from .widgets import Card, Row, Switch, pill, repolish

CLIPBOARD_CHOICES = ((15, "15 seconds"), (30, "30 seconds"), (60, "1 minute"),
                     (120, "2 minutes"), (0, "Never"))
_ICONS = {setup.OK: "✓", setup.WARN: "!", setup.FAIL: "✕"}


class _CheckWorker(QThread):
    """Runs the checklist off the UI thread (it probes the anisette server and systemd)."""
    done = Signal(object)

    def __init__(self, url: str, parent=None):
        super().__init__(parent)
        self._url = url

    def run(self):
        try:
            checks = setup.run_checks(self._url)
        except Exception as e:  # noqa: BLE001 - never take the page down
            checks = [setup.Check("error", "Couldn't run the checks", setup.FAIL, str(e))]
        try:
            services = setup.anisette_services()
            unit = services[0] if services else ""
            state = setup.service_state(unit) if unit else (False, False)
        except Exception:  # noqa: BLE001
            unit, state = "", (False, False)
        self.done.emit((checks, unit, state))


class _CheckRow(QFrame):
    """One checklist item: status mark, title, detail, and optional fix / copy buttons."""

    def __init__(self, check: setup.Check, page: "SettingsPage"):
        super().__init__(objectName="row")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 10, 12, 10)
        lay.setSpacing(10)
        mark = QLabel(_ICONS[check.state], objectName="checkIcon", alignment=Qt.AlignTop)
        mark.setProperty("state", check.state)
        lay.addWidget(mark)
        col = QVBoxLayout()
        col.setSpacing(3)
        col.addWidget(QLabel(check.title, objectName="checkTitle"))
        if check.detail:
            col.addWidget(QLabel(check.detail, objectName="checkDetail", wordWrap=True,
                                 textFormat=Qt.PlainText,
                                 textInteractionFlags=Qt.TextSelectableByMouse))
        if check.command and check.state != setup.OK:
            cmd = QLabel(check.command, objectName="command", textFormat=Qt.PlainText,
                         textInteractionFlags=Qt.TextSelectableByMouse, wordWrap=True)
            col.addWidget(cmd)
        lay.addLayout(col, 1)
        if check.command and check.state != setup.OK:
            b = pill("Copy command", "Copy this command to run it in a terminal")
            b.clicked.connect(lambda: page.copy_command(check.command))
            lay.addWidget(b, 0, Qt.AlignTop)
        if check.action:
            b = pill(check.action_label or "Fix", "Fix this automatically", accent=True)
            b.clicked.connect(lambda: page.run_action(check.action))
            lay.addWidget(b, 0, Qt.AlignTop)


def _section(title: str) -> QLabel:
    return QLabel(title.upper(), objectName="sectionTitle")


def _control_row(caption: str, detail: str, control: QWidget) -> Row:
    row = Row(caption)
    row.caption.setObjectName("checkTitle")
    row.value.setObjectName("checkDetail")
    row.value.setText(detail)
    row.value.setWordWrap(True)
    row.add(control)
    return row


class SettingsPage(QWidget):
    def __init__(self, window):
        super().__init__()
        self._w = window
        self._worker, self._pending = None, False
        col = QVBoxLayout(self)
        col.setContentsMargins(0, 0, 0, 0)
        col.setSpacing(10)
        col.addWidget(QLabel("Settings", objectName="pageTitle"))
        col.addSpacing(6)

        # --- setup checklist (first: it's what needs attention) ---
        head = QHBoxLayout()
        head.addWidget(_section("Setup checklist"))
        head.addStretch(1)
        self.recheck = pill("Check again", "Run all checks again")
        self.recheck.clicked.connect(self.refresh)
        head.addWidget(self.recheck)
        col.addLayout(head)
        self.summary = QLabel(objectName="summary")
        col.addWidget(self.summary)
        self.checks_card = Card()
        col.addWidget(self.checks_card)
        col.addSpacing(12)

        # --- appearance ---
        col.addWidget(_section("Appearance"))
        card = Card()
        seg = QFrame(objectName="segBox")
        sl = QHBoxLayout(seg)
        sl.setContentsMargins(3, 3, 3, 3)
        sl.setSpacing(2)
        self.theme_group = QButtonGroup(self, exclusive=True)
        for mode, label in (("auto", "Automatic"), ("light", "Light"), ("dark", "Dark")):
            b = QPushButton(label, objectName="seg", checkable=True, cursor=Qt.PointingHandCursor)
            b.setFocusPolicy(Qt.NoFocus)
            b.setProperty("mode", mode)
            b.setChecked(mode == window.theme_mode)
            self.theme_group.addButton(b)
            sl.addWidget(b)
        self.theme_group.buttonClicked.connect(lambda b: window.set_theme_mode(b.property("mode")))
        card.add(_control_row("Theme", "Automatic follows your system's light or dark setting.",
                              seg))
        col.addWidget(card)
        col.addSpacing(12)

        # --- security ---
        col.addWidget(_section("Clipboard"))
        card = Card()
        self.clip = QComboBox()
        for secs, label in CLIPBOARD_CHOICES:
            self.clip.addItem(label, secs)
        self.clip.setCurrentIndex(max(0, self.clip.findData(window.clipboard_seconds)))
        self.clip.currentIndexChanged.connect(
            lambda i: window.set_clipboard_seconds(self.clip.itemData(i)))
        card.add(_control_row("Clear copied passwords after",
                              "Passwords and codes are also kept out of KDE's clipboard history.",
                              self.clip))
        col.addWidget(card)
        col.addSpacing(12)

        # --- anisette server + startup ---
        col.addWidget(_section("Anisette server"))
        card = Card()
        self.url = QLineEdit(window.anisette_url, objectName="field",
                             placeholderText=setup.DEFAULT_ANISETTE_URL)
        self.url.setMinimumWidth(220)
        self.url.editingFinished.connect(self._url_changed)
        test = pill("Test", "Check that the server answers")
        test.clicked.connect(self._url_changed)
        box = QWidget()
        bl = QHBoxLayout(box)
        bl.setContentsMargins(0, 0, 0, 0)
        bl.addWidget(self.url)
        bl.addWidget(test)
        card.add(_control_row("Server address",
                              "Used by Sync now and by the checks below.", box))
        self.server_state = QLabel(objectName="checkDetail")
        self.server_btn = pill("Start", "")
        self.server_btn.clicked.connect(self._toggle_server)
        sb = QWidget()
        sbl = QHBoxLayout(sb)
        sbl.setContentsMargins(0, 0, 0, 0)
        sbl.addWidget(self.server_state)
        sbl.addWidget(self.server_btn)
        self.server_row = card.add(_control_row("Service", "", sb))
        self.boot_switch = Switch(window, "Start the anisette server when you log in")
        self.boot_switch.toggled.connect(self._toggle_boot)
        self.boot_row = card.add(_control_row(
            "Start anisette server at login",
            "Runs the server as a systemd user service, so syncing works after a reboot.",
            self.boot_switch))
        col.addWidget(card)
        col.addSpacing(12)

        col.addWidget(_section("Startup"))
        card = Card()
        self.gui_switch = Switch(window, "Open iCloud Passwords when you log in")
        self.gui_switch.setChecked(setup.gui_autostart_enabled())
        self.gui_switch.toggled.connect(
            lambda on: self._report(*setup.set_gui_autostart(on, window.anisette_url)))
        card.add(_control_row("Open iCloud Passwords at login",
                              "Starts minimised, ready when you need it.", self.gui_switch))
        col.addWidget(card)
        col.addSpacing(12)

        # --- account ---
        col.addWidget(_section("Account"))
        self.account_card = Card()
        col.addWidget(self.account_card)
        col.addSpacing(12)

        col.addWidget(_section("Files"))
        card = Card()
        folder = pill("Open folder", "Open the folder with the encrypted vault and settings")
        folder.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(paths.config_dir()))))
        card.add(_control_row("Data folder", str(paths.config_dir()), folder))
        col.addWidget(card)
        col.addStretch(1)

    # --- checks ---
    def refresh(self) -> None:
        """Re-run the checklist and refresh account and service state (in the background)."""
        if self._worker is not None:
            self._pending = True  # re-run once the current pass ends (e.g. a new URL)
            return
        self.recheck.setEnabled(False)
        self.recheck.setText("Checking…")
        self._worker = _CheckWorker(self._w.anisette_url, self)
        self._worker.done.connect(self._show_results)
        self._worker.start()
        self._fill_account()

    def _show_results(self, result) -> None:
        checks, unit, (enabled, active) = result
        self._worker.wait()
        self._worker.deleteLater()
        self._worker = None
        self.recheck.setEnabled(True)
        self.recheck.setText("Check again")
        if self._pending:
            self._pending = False
            self.refresh()

        self.checks_card.clear()
        for c in checks:
            self.checks_card.add(_CheckRow(c, self))
        self.checks_card.show_rows({})
        problems, warnings = setup.summary(checks)
        if problems:
            text, state = f"{problems} problem{'s' if problems > 1 else ''} to fix", setup.FAIL
        elif warnings:
            text, state = (f"Working - {warnings} suggestion{'s' if warnings > 1 else ''}",
                           setup.WARN)
        else:
            text, state = "Everything is set up", setup.OK
        self.summary.setText(text)
        self.summary.setProperty("state", state)
        repolish(self.summary)
        self._w.set_setup_state(problems)

        self._unit = unit
        self.server_row.setVisible(bool(unit))
        self.boot_row.setVisible(bool(unit))
        if unit:
            self.server_row.caption.setText(unit)
            self.server_row._caption = unit
            self.server_row.value.setText("Running" if active else "Stopped")
            self.server_btn.setText("Restart" if active else "Start")
            self.boot_switch.blockSignals(True)
            self.boot_switch.setChecked(enabled)
            self.boot_switch.blockSignals(False)

    def stop(self) -> None:
        """Wait for a running check before the window goes away."""
        self._pending = False
        if self._worker is not None:
            self._worker.wait(5000)

    def _fill_account(self) -> None:
        self.account_card.clear()
        for label, value in setup.account_info():
            row = Row(label, wrap=True)
            row.value.setText(value)
            self.account_card.add(row)
        self.account_card.show_rows({})

    # --- actions ---
    def run_action(self, action: str) -> None:
        url = self._w.anisette_url
        unit = getattr(self, "_unit", "")
        if action == "start_service" and unit:
            self._report(*setup.systemctl("start", unit), ok_text=f"Started {unit}")
        elif action == "restart_service" and unit:
            self._report(*setup.systemctl("restart", unit), ok_text=f"Restarted {unit}")
        elif action == "enable_service" and unit:
            self._report(*setup.systemctl("enable", "--now", unit),
                         ok_text=f"{unit} will start at login")
        elif action == "install_launcher":
            self._report(*setup.install_launcher(url))
        elif action == "sync":
            self._w.start_sync()
            return
        elif action == "open_extension":
            self._w.show_page("extension")
            return
        elif action == "login":
            argv = setup.terminal_argv(setup.login_command(url))
            if argv is None:
                self._w.toast.show_message("No terminal found - copy the command instead", 4000)
                return
            from .browsers import launch
            ok, err = launch(argv)
            if not ok:
                self._w.toast.show_message(f"Couldn't open a terminal: {err}", 4000)
                return
            self._w.toast.show_message("Finish signing in in the terminal, then check again",
                                       5000)
            return
        self.refresh()

    def _report(self, ok: bool, message: str, ok_text: str = "") -> None:
        text = (ok_text or message) if ok else f"Failed: {message.splitlines()[-1] if message else ''}"
        self._w.toast.show_message(text, 4000)

    def copy_command(self, command: str) -> None:
        QGuiApplication.clipboard().setText(command)
        self._w.toast.show_message("Command copied - paste it into a terminal")

    def _url_changed(self) -> None:
        self._w.set_anisette_url(self.url.text().strip())
        self.refresh()

    def _toggle_server(self) -> None:
        self.run_action("restart_service" if self.server_btn.text() == "Restart"
                        else "start_service")

    def _toggle_boot(self, on: bool) -> None:
        unit = getattr(self, "_unit", "")
        if not unit:
            return
        if on:
            self._report(*setup.systemctl("enable", unit), ok_text=f"{unit} will start at login")
        else:
            self._report(*setup.systemctl("disable", unit),
                         ok_text=f"{unit} won't start at login")
        self.refresh()
