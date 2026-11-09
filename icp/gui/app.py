"""Passwords: a GTK4 / libadwaita viewer for the local iCloud Keychain vault.

Read-only, like the rest of icp: browse and search logins, reveal/copy passwords, live
verification codes, sync status. Locks itself after a few minutes idle and wipes the in-memory
vault; unlocking reloads it (which asks the keyring again if needed)."""

from __future__ import annotations

import subprocess
import sys
import time
from datetime import datetime

try:
    import gi
except ImportError:  # venv without system site-packages: borrow the distro's PyGObject
    sys.path.append("/usr/lib/python3/dist-packages")
    import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, GLib, Gtk  # noqa: E402

from .. import status, totp as totp_codes  # noqa: E402

APP_ID = "org.icp.Passwords"
IDLE_LOCK_SECONDS = 5 * 60
CLIPBOARD_CLEAR_SECONDS = 30


def _ago(ts: float) -> str:
    d = max(0, time.time() - ts)
    for unit, n in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if d >= n:
            v = int(d // n)
            return f"{v} {unit}{'' if v == 1 else 's'} ago"
    return "just now"


class Window(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="Passwords", default_width=980, default_height=640)
        self.creds: list = []
        self.current = None
        self.revealed = False
        self.copy_token = 0
        self.last_activity = time.time()
        self.code_rows: list = []

        self.stack = Adw.ViewStack()
        self.set_content(self.stack)
        self.stack.add_named(self._build_main(), "main")
        self.stack.add_named(self._build_locked(), "locked")

        # any input counts as activity; the 1s tick refreshes codes and enforces the idle lock
        for ctl in (Gtk.EventControllerKey(), Gtk.EventControllerMotion()):
            ctl.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
            ctl.connect("key-pressed" if isinstance(ctl, Gtk.EventControllerKey) else "motion",
                        self._touch)
            self.add_controller(ctl)
        GLib.timeout_add_seconds(1, self._tick)
        self.unlock()

    # ---- building the UI -------------------------------------------------------------------
    def _build_main(self):
        self.search = Gtk.SearchEntry(placeholder_text="Search", hexpand=True)
        self.search.connect("search-changed", lambda *_: self.listbox.invalidate_filter())
        self.listbox = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self.listbox.add_css_class("navigation-sidebar")
        self.listbox.set_filter_func(self._filter)
        self.listbox.set_sort_func(self._sort)
        self.listbox.connect("row-selected", self._on_select)
        scroll = Gtk.ScrolledWindow(child=self.listbox, vexpand=True,
                                    hscrollbar_policy=Gtk.PolicyType.NEVER)

        self.sync_label = Gtk.Label(xalign=0, wrap=True, margin_start=12, margin_end=12,
                                    margin_top=6, margin_bottom=6)
        self.sync_label.add_css_class("caption")

        menu = Gtk.PopoverMenu.new_from_model(self._menu_model())
        menu_btn = Gtk.MenuButton(icon_name="open-menu-symbolic", popover=menu, tooltip_text="Menu")
        lock_btn = Gtk.Button(icon_name="changes-prevent-symbolic", tooltip_text="Lock")
        lock_btn.connect("clicked", lambda *_: self.lock())
        side_header = Adw.HeaderBar()
        side_header.set_title_widget(Gtk.Label(label="Passwords", css_classes=["heading"]))
        side_header.pack_start(lock_btn)
        side_header.pack_end(menu_btn)

        side_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        search_box = Gtk.Box(margin_start=8, margin_end=8, margin_top=8, margin_bottom=8)
        search_box.append(self.search)
        for w in (search_box, scroll, Gtk.Separator(), self.sync_label):
            side_box.append(w)
        side_view = Adw.ToolbarView(content=side_box)
        side_view.add_top_bar(side_header)

        self.detail_page = Adw.PreferencesPage()
        self.empty = Adw.StatusPage(icon_name="dialog-password-symbolic",
                                    title="No Login Selected",
                                    description="Choose a login from the list.")
        self.detail_stack = Gtk.Stack()
        self.detail_stack.add_named(self.empty, "empty")
        self.detail_stack.add_named(self.detail_page, "detail")
        self.toast = Adw.ToastOverlay(child=self.detail_stack)
        content_view = Adw.ToolbarView(content=self.toast)
        content_view.add_top_bar(Adw.HeaderBar())

        split = Adw.NavigationSplitView()
        split.set_sidebar(Adw.NavigationPage(child=side_view, title="Logins"))
        split.set_content(Adw.NavigationPage(child=content_view, title="Details"))
        return split

    def _menu_model(self):
        from gi.repository import Gio
        m = Gio.Menu()
        m.append("Sync now", "app.sync")
        m.append("Refresh keyring mirror", "app.mirror")
        m.append("Quit", "app.quit")
        return m

    def _build_locked(self):
        page = Adw.StatusPage(icon_name="changes-prevent-symbolic", title="Passwords Locked",
                              description="Your logins are cleared from memory while locked.")
        btn = Gtk.Button(label="Unlock", halign=Gtk.Align.CENTER, css_classes=["suggested-action",
                                                                                 "pill"])
        btn.connect("clicked", lambda *_: self.unlock())
        page.set_child(btn)
        view = Adw.ToolbarView(content=page)
        view.add_top_bar(Adw.HeaderBar())
        return view

    # ---- lock / unlock -----------------------------------------------------------------------
    def unlock(self):
        try:
            from ..vault.store import load_vault
            self.creds = load_vault().all()
        except Exception as e:
            self.creds = []
            self.stack.set_visible_child_name("locked")
            self._toast(f"Could not unlock: {e}")
            return
        self.last_activity = time.time()
        self._populate()
        self._refresh_sync()
        self.stack.set_visible_child_name("main")

    def lock(self):
        self.creds, self.current = [], None
        self._clear_list()
        self.detail_stack.set_visible_child_name("empty")
        self.stack.set_visible_child_name("locked")

    def _touch(self, *_a):
        self.last_activity = time.time()
        return False

    def _tick(self):
        if self.stack.get_visible_child_name() == "main":
            if time.time() - self.last_activity > IDLE_LOCK_SECONDS:
                self.lock()
            else:
                for paint in self.code_rows:
                    paint()
        return True

    # ---- list --------------------------------------------------------------------------------
    def _clear_list(self):
        while (row := self.listbox.get_row_at_index(0)) is not None:
            self.listbox.remove(row)

    def _populate(self):
        self._clear_list()
        for c in self.creds:
            row = Adw.ActionRow(title=GLib.markup_escape_text(c.title or c.domain),
                                subtitle=GLib.markup_escape_text(c.username or ""), activatable=True)
            avatar = Adw.Avatar(size=32, text=c.title or c.domain or "?", show_initials=True)
            row.add_prefix(avatar)
            row.cred = c
            self.listbox.append(row)

    def _filter(self, row):
        q = self.search.get_text().strip().lower()
        if not q:
            return True
        c = row.cred
        return q in f"{c.title} {c.domain} {c.username}".lower()

    @staticmethod
    def _sort(a, b):
        ka = (a.cred.title or a.cred.domain).lower()
        kb = (b.cred.title or b.cred.domain).lower()
        return (ka > kb) - (ka < kb)

    # ---- detail ------------------------------------------------------------------------------
    def _on_select(self, _lb, row):
        if row is None:
            return
        self.current, self.revealed = row.cred, False
        self._show_detail(row.cred)

    def _copy(self, text: str, what: str):
        clip = Gdk.Display.get_default().get_clipboard()
        if what in ("Password", "Code"):
            # x-kde-passwordManagerHint asks clipboard managers (Klipper, CopyQ, ...) not to record it
            clip.set_content(Gdk.ContentProvider.new_union([
                Gdk.ContentProvider.new_for_value(text),
                Gdk.ContentProvider.new_for_bytes("x-kde-passwordManagerHint",
                                                  GLib.Bytes.new(b"secret"))]))
        else:
            clip.set(text)
        self.copy_token += 1
        token = self.copy_token

        def clear():
            if token == self.copy_token:  # nothing newer was copied meanwhile
                clip.set("")
            return False
        GLib.timeout_add_seconds(CLIPBOARD_CLEAR_SECONDS, clear)
        self._toast(f"{what} copied - clears in {CLIPBOARD_CLEAR_SECONDS}s")

    def _toast(self, msg: str):
        self.toast.add_toast(Adw.Toast(title=msg, timeout=3))

    def _copy_btn(self, text_fn, what):
        b = Gtk.Button(icon_name="edit-copy-symbolic", valign=Gtk.Align.CENTER,
                       tooltip_text=f"Copy {what.lower()}", css_classes=["flat"])
        b.connect("clicked", lambda *_: self._copy(text_fn(), what))
        return b

    def _show_detail(self, c):
        page = Adw.PreferencesPage()
        self.code_rows = []
        group = Adw.PreferencesGroup(title=GLib.markup_escape_text(c.title or c.domain))

        site = Adw.ActionRow(title="Website", subtitle=GLib.markup_escape_text(c.domain),
                             subtitle_selectable=True)
        group.add(site)

        user = Adw.ActionRow(title="Username", subtitle=GLib.markup_escape_text(c.username or "-"),
                             subtitle_selectable=True)
        if c.username:
            user.add_suffix(self._copy_btn(lambda: c.username, "Username"))
        group.add(user)

        pw = Adw.ActionRow(title="Password", subtitle="••••••••••")
        eye = Gtk.ToggleButton(icon_name="view-reveal-symbolic", valign=Gtk.Align.CENTER,
                               tooltip_text="Show password", css_classes=["flat"])
        eye.connect("toggled", lambda b: pw.set_subtitle(
            GLib.markup_escape_text(c.password) if b.get_active() else "••••••••••"))
        pw.add_suffix(eye)
        pw.add_suffix(self._copy_btn(lambda: c.password, "Password"))
        group.add(pw)
        page.add(group)

        if c.totp:
            codes = Adw.PreferencesGroup(title="Verification Code")
            row = Adw.ActionRow(title="Code", subtitle="")
            row.add_css_class("monospace")

            def paint(row=row, c=c):
                t = totp_codes.generate(c.totp)
                if t:
                    left = max(0, int(t["expires"] - time.time()))
                    code = t["code"]
                    row.set_title(f"{code[:3]} {code[3:]}" if len(code) == 6 else code)
                    row.set_subtitle(f"changes in {left}s")
            paint()
            self.code_rows.append(paint)
            row.add_suffix(self._copy_btn(lambda: (totp_codes.generate(c.totp) or {}).get("code", ""),
                                          "Code"))
            codes.add(row)
            page.add(codes)

        if c.notes:
            ng = Adw.PreferencesGroup(title="Notes")
            ng.add(Adw.ActionRow(title=GLib.markup_escape_text(c.notes), title_lines=0))
            page.add(ng)

        when = c.last_used or c.mdat
        if when:
            info = Adw.PreferencesGroup()
            info.add(Adw.ActionRow(title="Last used" if c.last_used else "Last modified",
                                   subtitle=datetime.fromtimestamp(when).strftime("%b %d, %Y")))
            page.add(info)

        # swap the page in place
        self.detail_stack.remove(self.detail_page)
        self.detail_page = page
        self.detail_stack.add_named(page, "detail")
        self.detail_stack.set_visible_child_name("detail")

    def select_key(self, key: str):
        from ..mirror import item_id
        self.search.set_text("")
        i = 0
        while (row := self.listbox.get_row_at_index(i)) is not None:
            if item_id(row.cred.domain, row.cred.username) == key:
                self.listbox.select_row(row)
                row.grab_focus()
                return
            i += 1

    # ---- sync status & actions -----------------------------------------------------------------
    def _refresh_sync(self):
        s = status.read()
        n = len(self.creds)
        if s.get("failures"):
            txt = f"{n} logins · sync failing" + (f": {s['hint']}" if s.get("hint") else "")
            self.sync_label.add_css_class("error")
        elif s.get("last_success"):
            txt = f"{n} logins · synced {_ago(s['last_success'])}"
            self.sync_label.remove_css_class("error")
        else:
            txt = f"{n} logins · not synced yet"
        self.sync_label.set_label(txt)

    def run_cli(self, *args):
        self._toast(f"Running icp {' '.join(args)}…")

        def work():
            r = subprocess.run([sys.executable, "-m", "icp.cli.app", *args],
                               capture_output=True, text=True)
            GLib.idle_add(self._done, args, r)
        import threading
        threading.Thread(target=work, daemon=True).start()

    def _done(self, args, r):
        msg = (r.stdout.strip().splitlines() or r.stderr.strip().splitlines() or ["done"])[-1]
        self._toast(msg)
        if args[0] == "sync" and self.stack.get_visible_child_name() == "main":
            self.unlock()
        return False


class App(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID)
        from .search import SearchProvider
        # stay alive a while after a Shell search so follow-up keystrokes are fast
        self.set_inactivity_timeout(5 * 60 * 1000)
        self.provider = SearchProvider(self._open_login, self._open_search)

    def do_dbus_register(self, connection, object_path):
        self.provider.register(connection)
        return Adw.Application.do_dbus_register(self, connection, object_path)

    def _window(self):
        win = self.props.active_window or Window(self)
        win.present()
        return win

    def _open_login(self, key):
        win = self._window()
        win.select_key(key)

    def _open_search(self, text):
        win = self._window()
        win.search.set_text(text)

    def do_startup(self):
        Adw.Application.do_startup(self)
        from gi.repository import Gio
        for name, fn in (("sync", lambda *_: self.props.active_window.run_cli("sync")),
                         ("mirror", lambda *_: self.props.active_window.run_cli("mirror")),
                         ("quit", lambda *_: self.quit())):
            act = Gio.SimpleAction.new(name, None)
            act.connect("activate", fn)
            self.add_action(act)
        self.set_accels_for_action("app.quit", ["<Control>q"])

    def do_activate(self):
        self._window()


def main() -> int:
    return App().run(sys.argv[:1])
