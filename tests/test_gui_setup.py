"""Offline tests for the desktop app's setup checklist and startup helpers (icp/gui/setup.py).
systemd, the anisette probe and browser registration are stubbed; files go to temp dirs.

Run: .venv/bin/python -m unittest tests.test_gui_setup
"""

import os
import tempfile
import time
import unittest
from unittest import mock

from icp.gui import setup


class _TempHome(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._env = mock.patch.dict(os.environ, {
            "XDG_CONFIG_HOME": os.path.join(self._tmp.name, "config"),
            "XDG_DATA_HOME": os.path.join(self._tmp.name, "data")})
        self._env.start()
        os.environ.pop("DBUS_SESSION_BUS_ADDRESS", None)

    def tearDown(self):
        self._env.stop()
        self._tmp.cleanup()


def _stub(services=(), state=(False, False), probe=(True, "responding"), hosts=()):
    return [mock.patch.object(setup, "anisette_services", return_value=list(services)),
            mock.patch.object(setup, "service_state", return_value=state),
            mock.patch.object(setup, "probe_anisette", return_value=probe),
            mock.patch("icp.gui.browsers.any_connected",
                       return_value=(len(hosts), len(hosts) + 1))]


class ChecklistTests(_TempHome):
    def checks(self, url="http://127.0.0.1:6970", **kw):
        patches = _stub(**kw)
        for p in patches:
            p.start()
        try:
            return {c.key: c for c in setup.run_checks(url)}
        finally:
            for p in patches:
                p.stop()

    def test_missing_url_is_a_problem_with_a_command(self):
        c = self.checks(url="")["anisette_url"]
        self.assertEqual(c.state, setup.FAIL)
        self.assertIn("ICP_ANISETTE_URL", c.command)

    def test_stopped_service_offers_start(self):
        c = self.checks(services=["anisette-rs.service"], state=(True, False),
                        probe=(False, "not reachable"))["anisette_up"]
        self.assertEqual((c.state, c.action), (setup.FAIL, "start_service"))
        self.assertIn("systemctl --user start anisette-rs.service", c.command)

    def test_disabled_service_offers_enable(self):
        c = self.checks(services=["anisette-rs.service"], state=(False, True))["anisette_boot"]
        self.assertEqual((c.state, c.action), (setup.WARN, "enable_service"))

    def test_no_service_is_only_a_warning(self):
        c = self.checks()["anisette_boot"]
        self.assertEqual(c.state, setup.WARN)
        self.assertFalse(c.action)

    def test_not_signed_in_offers_terminal_login(self):
        c = self.checks()["signed_in"]
        self.assertEqual((c.state, c.action), (setup.FAIL, "login"))
        self.assertTrue(c.command.endswith("login"))
        self.assertIn("ICP_ANISETTE_URL=http://127.0.0.1:6970", c.command)

    def test_stale_vault_offers_sync(self):
        from icp import paths, ratelimit
        paths.session_file().write_bytes(b"x")
        paths.vault_file().write_bytes(b"x")
        ratelimit.save({"last_success": time.time() - 3 * 86400})
        with mock.patch("icp.auth.session.load", return_value={"octagon": {"peer_id": "p"}}):
            checks = self.checks()
        self.assertEqual(checks["signed_in"].state, setup.OK)
        self.assertEqual((checks["vault"].state, checks["vault"].action), (setup.WARN, "sync"))

    def test_browser_and_launcher(self):
        checks = self.checks(hosts=["Zen"])
        self.assertEqual(checks["browser"].state, setup.OK)
        self.assertIn("1 of 2", checks["browser"].detail)
        missing = self.checks()["browser"]
        self.assertEqual((missing.state, missing.action), (setup.WARN, "open_extension"))
        self.assertEqual(checks["launcher"].action, "install_launcher")

    def test_summary(self):
        checks = [setup.Check("a", "", setup.FAIL), setup.Check("b", "", setup.WARN),
                  setup.Check("c", "", setup.OK)]
        self.assertEqual(setup.summary(checks), (1, 1))


class DesktopFileTests(_TempHome):
    def test_launcher_bakes_in_the_url(self):
        setup.install_launcher("http://127.0.0.1:6970")
        text = setup.launcher_file().read_text()
        self.assertIn("Exec=env ICP_ANISETTE_URL=http://127.0.0.1:6970 ", text)
        self.assertNotIn("--minimized", text)

    def test_autostart_toggle(self):
        self.assertFalse(setup.gui_autostart_enabled())
        setup.set_gui_autostart(True, "")
        self.assertTrue(setup.gui_autostart_enabled())
        self.assertIn("--minimized", setup.autostart_file().read_text())
        setup.set_gui_autostart(False, "")
        self.assertFalse(setup.gui_autostart_enabled())

    def test_terminal_argv(self):
        with mock.patch("shutil.which", side_effect=lambda n: n == "konsole" and "/usr/bin/konsole"):
            self.assertEqual(setup.terminal_argv(["icp", "login"]),
                             ["konsole", "-e", "icp", "login"])
        with mock.patch("shutil.which", return_value=None):
            self.assertIsNone(setup.terminal_argv(["icp"]))


if __name__ == "__main__":
    unittest.main()
