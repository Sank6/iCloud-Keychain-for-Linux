"""Offline tests for browser discovery and extension setup (icp/gui/browsers.py), against a
fake home directory.

Run: .venv/bin/python -m unittest tests.test_gui_browsers
"""

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from icp.gui import browsers as b

ZEN = next(s for s in b.SPECS if s.key == "zen")
CHROME = next(s for s in b.SPECS if s.key == "chrome")


class _FakeHome(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)
        self._patches = [mock.patch.object(b, "_home", return_value=self.home),
                         mock.patch.dict(os.environ, {"XDG_DATA_HOME": str(self.home / "data")})]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        self._tmp.cleanup()

    def write_json(self, path: Path, data) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data))


class IdTests(unittest.TestCase):
    def test_predicted_id_matches_chromium_scheme(self):
        path = os.path.realpath(b.EXTENSION_DIR)
        hexed = hashlib.sha256(path.encode()).hexdigest()[:32]
        expected = "".join("abcdefghijklmnop"[int(c, 16)] for c in hexed)
        self.assertEqual(b.predicted_chromium_id(), expected)
        self.assertEqual(len(expected), 32)
        self.assertTrue(set(expected) <= set("abcdefghijklmnop"))


class ScanTests(_FakeHome):
    def test_finds_profile_only_browser_and_skips_absent_ones(self):
        (self.home / ".zen").mkdir()
        with mock.patch("shutil.which", return_value=None), \
                mock.patch("os.access", return_value=False), \
                mock.patch.object(b, "_flatpak_installed", return_value=False):
            found = {i.key for i in b.scan()}
        self.assertEqual(found, {"zen:system"})

    def test_flatpak_paths(self):
        inst = b.Install(CHROME, b.FLATPAK, ("flatpak", "run", CHROME.flatpak),
                         self.home / ".var/app" / CHROME.flatpak)
        self.assertEqual(inst.host_dirs(),
                         [self.home / ".var/app/com.google.Chrome/config/google-chrome/"
                                      "NativeMessagingHosts"])
        self.assertEqual(inst.label, "Google Chrome (Flatpak)")

    def test_firefox_fork_writes_own_and_mozilla_dirs(self):
        inst = b.Install(ZEN, b.SYSTEM, ("zen",), self.home)
        self.assertEqual(inst.host_dirs(), [self.home / ".zen/native-messaging-hosts",
                                            self.home / ".mozilla/native-messaging-hosts",
                                            self.home / ".config/mozilla/native-messaging-hosts"])

    def test_firefox_xdg_profiles(self):
        ff = b.Install(next(s for s in b.SPECS if s.key == "firefox"), b.SYSTEM, ("firefox",),
                       self.home)
        self.assertEqual(ff.data_dir(), self.home / ".mozilla/firefox")  # nothing yet: legacy
        (self.home / ".config/mozilla/firefox").mkdir(parents=True)
        self.assertEqual(ff.data_dir(), self.home / ".config/mozilla/firefox")
        self.assertIn(self.home / ".config/mozilla/native-messaging-hosts", ff.host_dirs())


class StatusTests(_FakeHome):
    def test_firefox_temporary_addon(self):
        ff = b.Install(next(s for s in b.SPECS if s.key == "firefox"), b.SYSTEM, ("firefox",),
                       self.home)
        self.write_json(self.home / ".config/mozilla/firefox/x.default-release/extensions.json",
                        {"addons": [{"id": b.GECKO_ID, "active": True,
                                     "location": "app-temporary"}]})
        b.register_host(ff, "")
        st = b.status(ff)
        self.assertEqual((st.extension, st.temporary, st.host), ("installed", True, True))
        self.assertTrue(b.guided(ff, st))
        self.assertIn("restarts", b.next_step(ff, st))

    def test_firefox_extension_and_unsigned_pref(self):
        inst = b.Install(ZEN, b.SYSTEM, ("zen",), self.home)
        self.assertEqual(b.status(inst).extension, "missing")
        prof = self.home / ".zen/abc.Default"
        self.write_json(prof / "extensions.json", {"addons": [{"id": b.GECKO_ID, "active": True}]})
        (prof / "user.js").write_text('user_pref("xpinstall.signatures.required", false);\n')
        st = b.status(inst)
        self.assertEqual((st.extension, st.unsigned_ok, st.host), ("installed", True, False))

    def test_chromium_reads_real_id_and_register_uses_it(self):
        inst = b.Install(CHROME, b.SYSTEM, ("google-chrome",), self.home)
        prefs = self.home / ".config/google-chrome/Default/Secure Preferences"
        self.write_json(prefs, {"extensions": {"settings": {
            "realidrealidrealidrealidrealidre": {"path": str(b.EXTENSION_DIR), "state": 1},
            "someotherextension": {"path": "/elsewhere", "state": 1}}}})
        st = b.status(inst)
        self.assertEqual((st.extension, st.ext_id), ("installed", "realidrealidrealidrealidrealidre"))
        self.assertFalse(st.host)
        b.register_host(inst, "http://127.0.0.1:6970", st.ext_id)
        st = b.status(inst)
        self.assertTrue(st.host)
        manifest = json.loads((inst.host_dirs()[0] / "org.icp.native.json").read_text())
        self.assertEqual(manifest["allowed_origins"],
                         ["chrome-extension://realidrealidrealidrealidrealidre/"])
        wrapper = Path(manifest["path"]).read_text()
        self.assertIn("ICP_ANISETTE_URL=http://127.0.0.1:6970", wrapper)

    def test_disabled_extension(self):
        inst = b.Install(CHROME, b.SYSTEM, ("google-chrome",), self.home)
        self.write_json(self.home / ".config/google-chrome/Default/Preferences",
                        {"extensions": {"settings": {"x" * 32: {
                            "path": str(b.EXTENSION_DIR), "state": 0}}}})
        self.assertEqual(b.status(inst).extension, "disabled")

    def test_flatpak_register_goes_through_flatpak_spawn(self):
        inst = b.Install(CHROME, b.FLATPAK, ("flatpak", "run", CHROME.flatpak),
                         self.home / ".var/app" / CHROME.flatpak)
        b.register_host(inst, "")
        manifest = json.loads((inst.host_dirs()[0] / "org.icp.native.json").read_text())
        inner = Path(manifest["path"])
        self.assertTrue(str(inner).startswith(str(inst.root)))  # visible inside the sandbox
        self.assertIn("flatpak-spawn --host", inner.read_text())
        with mock.patch.object(b, "flatpak_talk_granted", return_value=False):
            st = b.status(inst)
        self.assertTrue(st.host)
        self.assertFalse(st.sandbox_ok)
        loaded = b.Status("installed", st.ext_id, st.host, st.sandbox_ok, True)
        self.assertIn("Flatpak", b.next_step(inst, loaded))


class KeepOptionTests(_FakeHome):
    def ff(self, key="firefox"):
        return b.Install(next(s for s in b.SPECS if s.key == key), b.SYSTEM, ("x",), self.home)

    def test_release_firefox_gets_system_folder(self):
        with mock.patch.object(b, "build_flags", return_value={
                "MOZ_REQUIRE_SIGNING": True, "MOZ_UNSIGNED_SYSTEM_SCOPE": True}):
            opt = b.keep_option(self.ff())
        self.assertEqual(opt.kind, "system")
        self.assertIn("sudo install -Dm644", opt.command)
        self.assertIn(str(b.SYSTEM_EXTENSIONS / "icp-linux@local.xpi"), opt.command)

    def test_release_without_unsigned_scope_is_temporary_only(self):
        with mock.patch.object(b, "build_flags", return_value={"MOZ_REQUIRE_SIGNING": True}):
            self.assertEqual(b.keep_option(self.ff()).kind, "")

    def test_fork_gets_pref_and_it_is_written_once(self):
        with mock.patch.object(b, "build_flags", return_value={"MOZ_REQUIRE_SIGNING": False}):
            opt = b.keep_option(self.ff("zen"))
        self.assertEqual(opt.kind, "pref")
        self.assertIn("not just", opt.warning)
        prof = self.home / ".zen/abc.default"
        prof.mkdir(parents=True)
        (prof / "prefs.js").write_text("")
        inst = self.ff("zen")
        self.assertEqual(b.turn_off_signing(inst), 1)
        b.turn_off_signing(inst)
        text = (prof / "user.js").read_text()
        self.assertEqual(text.count('user_pref("xpinstall.signatures.required", false);'), 1)
        self.assertTrue(b.unsigned_allowed(inst))


class PageArgvTests(_FakeHome):
    def test_open_targets(self):
        chrome = b.Install(CHROME, b.SYSTEM, ("google-chrome",), self.home)
        edge = b.Install(next(s for s in b.SPECS if s.key == "edge"), b.SYSTEM, ("edge",),
                         self.home)
        zen = b.Install(ZEN, b.SYSTEM, ("zen",), self.home)
        st = b.Status("missing", "", False, True, False)
        # chrome:// URLs from the command line are refused, so only the browser is opened.
        self.assertEqual(b.extensions_page_argv(chrome, st), ["google-chrome", "--new-window"])
        self.assertEqual(b.extensions_url(edge), "edge://extensions")
        self.assertEqual(b.extensions_page_argv(zen, st), ["zen", "--new-window"])
        self.assertTrue(b.guided(zen, st))  # signed-only: pasted about:debugging steps
        xpi = b.extensions_page_argv(zen, b.Status("missing", "", False, True, True))[-1]
        self.assertTrue(xpi.endswith(".xpi") and Path(xpi).exists())


if __name__ == "__main__":
    unittest.main()
