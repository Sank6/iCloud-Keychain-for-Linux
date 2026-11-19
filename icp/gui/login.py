"""Graphical Apple sign-in: `icp login --gui` (also reachable from the Passwords app and the browser
popup). A form for Apple ID + password, then the usual flow with 2FA code and join confirmation
asked in dialogs. All logic lives in `loginflow.py`; this file is only widgets."""

from __future__ import annotations

import threading

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk  # noqa: E402

from .. import account  # noqa: E402
from ..cli import ui  # noqa: E402
from .loginflow import LoginFlow, MAX_PASSWORD_TRIES, Outcome  # noqa: E402


class LoginWindow(Adw.ApplicationWindow):
    def __init__(self, app, args):
        super().__init__(application=app, title="Sign in to iCloud", default_width=480,
                         default_height=560)
        self.args = args
        self.flow: LoginFlow | None = None
        self.bad_passwords = 0
        self._lines: list[str] = []
        self._prompt_dialog = None

        self.stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE)
        self.stack.add_named(self._build_form(), "form")
        self.stack.add_named(self._build_progress(), "progress")
        self.stack.add_named(self._build_result(), "result")
        view = Adw.ToolbarView(content=self.stack)
        view.add_top_bar(Adw.HeaderBar())
        self.set_content(view)
        self.connect("close-request", self._on_close)
        self._prefill()

    # ---- pages ------------------------------------------------------------------------------
    def _build_form(self):
        page = Adw.PreferencesPage()
        group = Adw.PreferencesGroup(
            title="Apple ID",
            description="Used only to talk to Apple. Nothing is changed in your account; the "
                        "app is read-only.")
        self.user_row = Adw.EntryRow(title="Apple ID (email)")
        self.pass_row = Adw.PasswordEntryRow(title="Password")
        self.remember = Adw.SwitchRow(
            title="Remember in the login keyring",
            subtitle="Lets sync refresh itself when it expires. Visible in Seahorse.",
            active=not getattr(self.args, "no_save_password", False))
        for row in (self.user_row, self.pass_row, self.remember):
            group.add(row)
        for row in (self.user_row, self.pass_row):
            row.connect("entry-activated", lambda *_: self._submit())
        page.add(group)
        self.form_error = Gtk.Label(wrap=True, xalign=0, css_classes=["error"], visible=False,
                                    margin_start=18, margin_end=18)
        btn = Gtk.Button(label="Sign In", halign=Gtk.Align.CENTER,
                         css_classes=["suggested-action", "pill"], margin_top=6)
        btn.connect("clicked", lambda *_: self._submit())
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        box.append(page)
        box.append(self.form_error)
        box.append(btn)
        page.set_vexpand(True)
        return box

    def _build_progress(self):
        self.progress_page = Adw.StatusPage(title="Signing in…",
                                            description="Follow the prompts that appear.")
        self.spinner = Gtk.Spinner(spinning=True, width_request=32, height_request=32)
        self.log = Gtk.Label(wrap=True, xalign=0, selectable=True, margin_start=16, margin_end=16)
        self.log.add_css_class("dim-label")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.append(self.spinner)
        box.append(self.log)
        cancel = Gtk.Button(label="Cancel", halign=Gtk.Align.CENTER)
        cancel.connect("clicked", lambda *_: self._cancel())
        box.append(cancel)
        self.progress_page.set_child(box)
        return self.progress_page

    def _build_result(self):
        self.result_page = Adw.StatusPage()
        self.result_btn = Gtk.Button(halign=Gtk.Align.CENTER, css_classes=["pill"])
        self.result_btn.connect("clicked", self._result_clicked)
        self.result_page.set_child(self.result_btn)
        return self.result_page

    # ---- form -------------------------------------------------------------------------------
    def _prefill(self):
        user = self.args.username
        pw = None
        if not user:
            user, pw = account.load(interactive=True)
        self.user_row.set_text(user or "")
        self.pass_row.set_text(pw or "")
        (self.pass_row if user else self.user_row).grab_focus()

    def _submit(self):
        user, pw = self.user_row.get_text().strip(), self.pass_row.get_text()
        if "@" not in user and not user.isdigit():
            return self._form_error("Enter your Apple ID (usually an email address).")
        if not pw:
            return self._form_error("Enter your password.")
        self.form_error.set_visible(False)
        self.args.username = user
        self.args.no_save_password = not self.remember.get_active()
        self._lines.clear()
        self.log.set_label("")
        self.progress_page.set_title("Signing in…")
        self.stack.set_visible_child_name("progress")
        self.flow = LoginFlow(self.args, progress=self._on_progress, ask_text=self._ask_text,
                              ask_secret=self._ask_secret, ask_confirm=self._ask_confirm,
                              done=lambda o: GLib.idle_add(self._finished, o))
        self.flow.password = pw
        self.pass_row.set_text("")      # don't keep the typed password in a widget
        self.flow.start()

    def _form_error(self, text: str):
        self.form_error.set_label(text)
        self.form_error.set_visible(True)

    def _cancel(self):
        if self.flow:
            self.flow.cancel()
            self._release_prompt()
        self.progress_page.set_title("Cancelling…")

    def _on_close(self, *_):
        self._cancel()
        return False

    # ---- progress ---------------------------------------------------------------------------
    def _on_progress(self, text: str):
        GLib.idle_add(self._add, text)

    def _add(self, text: str):
        if text:
            self._lines.append(text)
            self.log.set_label("\n".join(self._lines[-6:]))
        return False

    # ---- prompts: called on the worker thread, answered on the GTK thread ------------------------
    def _ask(self, heading: str, *, secret: bool = False, confirm: bool = False,
             body: str = "", ok_label: str = "Continue"):
        done = threading.Event()
        box = {"v": None}

        def show():
            d = Adw.MessageDialog(transient_for=self, heading=heading, body=body)
            entry = None
            if not confirm:
                entry = Gtk.PasswordEntry(show_peek_icon=True) if secret else Gtk.Entry()
                entry.set_activates_default(True)
                d.set_extra_child(entry)
            d.add_response("cancel", "Cancel" if not confirm else "Not now")
            d.add_response("ok", ok_label)
            d.set_response_appearance(
                "ok", Adw.ResponseAppearance.DESTRUCTIVE if confirm
                else Adw.ResponseAppearance.SUGGESTED)
            d.set_default_response("cancel" if confirm else "ok")

            def resp(_d, r):
                box["v"] = (r == "ok") if confirm else (entry.get_text() if r == "ok" else None)
                self._prompt_dialog = None
                done.set()
            d.connect("response", resp)
            self._prompt_dialog = (d, done, box)
            d.present()
            return False
        GLib.idle_add(show)
        done.wait()
        return box["v"]

    def _release_prompt(self):
        if self._prompt_dialog:
            d, done, _box = self._prompt_dialog
            GLib.idle_add(d.close)
            done.set()

    def _ask_text(self, msg: str) -> str:
        v = self._ask(msg.strip().rstrip(":"))
        if v is None:
            raise ui.Cancelled()
        return v.strip()

    def _ask_secret(self, msg: str) -> str:
        v = self._ask(msg.strip().rstrip(":"), secret=True)
        if v is None:
            raise ui.Cancelled()
        return v

    def _ask_confirm(self, msg: str) -> bool:
        body = "\n".join(self._lines[-3:])
        return bool(self._ask("Join iCloud Keychain?", confirm=True, body=body,
                              ok_label="Proceed"))

    # ---- result -----------------------------------------------------------------------------
    def _finished(self, o: Outcome):
        if o.credentials_wrong:
            self.bad_passwords += 1
        ok_icon = "emblem-ok-symbolic"
        self.result_page.set_icon_name(ok_icon if o.ok else "dialog-error-symbolic")
        self.result_page.set_title(o.title)
        detail = o.detail
        if o.credentials_wrong and self.bad_passwords >= MAX_PASSWORD_TRIES:
            detail += "\n\nStop and check your password at appleid.apple.com before trying again."
        self.result_page.set_description(detail)
        self.result_btn.set_label("Done" if o.ok else ("Try again" if o.retry else "Close"))
        self._retry = not o.ok and o.retry and not (o.credentials_wrong and
                                                    self.bad_passwords >= MAX_PASSWORD_TRIES)
        self.stack.set_visible_child_name("result")
        return False

    def _result_clicked(self, *_):
        if getattr(self, "_retry", False):
            self.stack.set_visible_child_name("form")
            self.pass_row.grab_focus()
        else:
            self.close()


def run(args) -> int:
    app = Adw.Application(application_id="org.icp.Login")
    app.connect("activate", lambda a: LoginWindow(a, args).present())
    return app.run([])
