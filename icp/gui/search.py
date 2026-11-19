"""GNOME Shell search provider (org.gnome.Shell.SearchProvider2) for the Passwords app.

Type a site or username in Activities and matching logins appear. Results show only the title
and username - never passwords. Activating a result opens the Passwords window on that login.
The vault is loaded on first query and dropped again after a few idle minutes."""

from __future__ import annotations

import time

from gi.repository import Gio, GLib

from ..mirror import item_id

OBJECT_PATH = "/org/icp/Passwords/SearchProvider"
IDLE_DROP = 5 * 60
MAX_RESULTS = 8

XML = """
<node><interface name="org.gnome.Shell.SearchProvider2">
 <method name="GetInitialResultSet"><arg type="as" direction="in"/><arg type="as" direction="out"/></method>
 <method name="GetSubsearchResultSet"><arg type="as" direction="in"/><arg type="as" direction="in"/><arg type="as" direction="out"/></method>
 <method name="GetResultMetas"><arg type="as" direction="in"/><arg type="aa{sv}" direction="out"/></method>
 <method name="ActivateResult"><arg type="s" direction="in"/><arg type="as" direction="in"/><arg type="u" direction="in"/></method>
 <method name="LaunchSearch"><arg type="as" direction="in"/><arg type="u" direction="in"/></method>
</interface></node>"""


class SearchProvider:
    def __init__(self, on_activate, on_launch):
        self._on_activate, self._on_launch = on_activate, on_launch
        self._creds: dict[str, object] = {}
        self._loaded = 0.0

    def register(self, connection) -> int:
        info = Gio.DBusNodeInfo.new_for_xml(XML).interfaces[0]
        return connection.register_object(OBJECT_PATH, info, self._call, None, None)

    def _load(self) -> None:
        if self._creds and time.time() - self._loaded < IDLE_DROP:
            self._loaded = time.time()
            return
        try:
            from ..vault.store import load_vault
            self._creds = {item_id(c.domain, c.username): c for c in load_vault().all()
                           if c.domain}
        except Exception:
            self._creds = {}
        self._loaded = time.time()
        GLib.timeout_add_seconds(IDLE_DROP + 5, self._maybe_drop)

    def _maybe_drop(self) -> bool:
        if time.time() - self._loaded >= IDLE_DROP:
            self._creds = {}
            return False
        return True

    def _find(self, terms: list[str]) -> list[str]:
        self._load()
        terms = [t.lower() for t in terms if t]
        if not terms:
            return []
        hits = []
        for key, c in self._creds.items():
            hay = f"{c.title} {c.domain} {c.username}".lower()
            if all(t in hay for t in terms):
                hits.append((-(c.last_used or c.mdat), (c.title or c.domain).lower(), key))
        hits.sort()
        return [k for _, _, k in hits[:MAX_RESULTS]]

    def _metas(self, ids: list[str]) -> list[dict]:
        out = []
        for key in ids:
            c = self._creds.get(key)
            if not c:
                continue
            out.append({
                "id": GLib.Variant("s", key),
                "name": GLib.Variant("s", c.title or c.domain),
                "description": GLib.Variant("s", c.username or c.domain),
                "gicon": GLib.Variant("s", "dialog-password-symbolic"),
            })
        return out

    def _call(self, _conn, _sender, _path, _iface, method, params, invocation):
        args = params.unpack()
        if method == "GetInitialResultSet":
            invocation.return_value(GLib.Variant("(as)", (self._find(args[0]),)))
        elif method == "GetSubsearchResultSet":
            invocation.return_value(GLib.Variant("(as)", (self._find(args[1]),)))
        elif method == "GetResultMetas":
            invocation.return_value(GLib.Variant("(aa{sv})", (self._metas(args[0]),)))
        elif method == "ActivateResult":
            self._on_activate(args[0])
            invocation.return_value(None)
        elif method == "LaunchSearch":
            self._on_launch(" ".join(args[0]))
            invocation.return_value(None)
        else:
            invocation.return_dbus_error("org.freedesktop.DBus.Error.UnknownMethod", method)
