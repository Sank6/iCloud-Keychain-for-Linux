"""Graphical Apple sign-in: `icp login --gui`.

Runs the normal `cmd_login` flow on a worker thread and swaps the terminal prompts in
`icp.cli.ui` for dialogs, so the password, the 2FA code and the irreversible-join confirmation
never need a terminal. Progress lines appear in the window. Nothing about the flow, pacing or
Apple-facing behaviour changes; only where the questions are asked."""

from __future__ import annotations

import argparse
import threading

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk  # noqa: E402

from ..cli import ui  # noqa: E402


class LoginWindow(Adw.ApplicationWindow):
    def __init__(self, app, args):
        super().__init__(application=app, title="Sign in to iCloud", default_width=520,
                         default_height=420)
        self.args = args
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        box.append(Adw.HeaderBar())
        self.status = Adw.StatusPage(icon_name="dialog-password-symbolic",
                                     title="Signing in…",
                                     description="Follow the prompts.")
        self.log = Gtk.Label(wrap=True, xalign=0, selectable=True, margin_start=16,
                             margin_end=16, margin_bottom=16)
        self.log.add_css_class("dim-label")
        self.status.set_child(self.log)
        box.append(self.status)
        self.set_content(box)
        self._lines: list[str] = []
        self._patch_ui()
        threading.Thread(target=self._work, daemon=True).start()

    # ---- progress -----------------------------------------------------------------------
    def _add(self, text: str):
        self._lines.append(text)
        self.log.set_label("\n".join(self._lines[-8:]))
        return False

    def _patch_ui(self):
        ui.out = lambda m="": GLib.idle_add(self._add, m)
        ui.step = lambda m: GLib.idle_add(self._add, m)
        ui.warn = lambda m: GLib.idle_add(self._add, f"warning: {m}")

        def err(m):
            ui.last_error = m
            GLib.idle_add(self._add, f"error: {m}")
        ui.err = err
        ui.ask = lambda m: self._prompt(m, secret=False)
        ui.secret = lambda m: self._prompt(m, secret=True)
        ui.confirm_yn = lambda m: self._confirm(m)

    # ---- prompts (called on the worker thread, answered on the GTK thread) ----------------
    def _prompt(self, msg: str, *, secret: bool) -> str:
        done, box = threading.Event(), {"v": ""}

        def show():
            d = Adw.MessageDialog(transient_for=self, heading=msg.strip().rstrip(":"))
            entry = Gtk.PasswordEntry(show_peek_icon=True) if secret else Gtk.Entry()
            entry.set_activates_default(True)
            d.set_extra_child(entry)
            d.add_response("cancel", "Cancel")
            d.add_response("ok", "Continue")
            d.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
            d.set_default_response("ok")

            def resp(_d, r):
                box["v"] = entry.get_text() if r == "ok" else ""
                done.set()
            d.connect("response", resp)
            d.present()
            return False
        GLib.idle_add(show)
        done.wait()
        return box["v"].strip() if not secret else box["v"]

    def _confirm(self, msg: str) -> bool:
        done, box = threading.Event(), {"v": False}

        def show():
            d = Adw.MessageDialog(transient_for=self, heading="Join iCloud Keychain?",
                                  body="\n".join(self._lines[-3:]))
            d.add_response("no", "Not now")
            d.add_response("yes", "Proceed")
            d.set_response_appearance("yes", Adw.ResponseAppearance.DESTRUCTIVE)
            d.set_default_response("no")

            def resp(_d, r):
                box["v"] = r == "yes"
                done.set()
            d.connect("response", resp)
            d.present()
            return False
        GLib.idle_add(show)
        done.wait()
        return box["v"]

    # ---- flow -----------------------------------------------------------------------------
    def _work(self):
        from ..cli.app import cmd_login
        try:
            rc = cmd_login(self.args)
        except Exception as e:  # shown, not swallowed silently
            ui.err(str(e))
            rc = 1
        GLib.idle_add(self._finished, rc)

    def _finished(self, rc: int):
        ok = rc == 0
        self.status.set_icon_name("emblem-ok-symbolic" if ok else "dialog-error-symbolic")
        self.status.set_title("Signed in" if ok else "Sign-in did not finish")
        self.status.set_description("You can close this window." if ok
                                    else "See the messages below, then try again later.")
        return False


def run(args) -> int:
    app = Adw.Application(application_id="io.github.icp.Login")
    app.connect("activate", lambda a: LoginWindow(a, args).present())
    return app.run([])


def default_args(anisette=None) -> argparse.Namespace:
    return argparse.Namespace(username=None, no_save_password=False, debug=False,
                              anisette=anisette)
