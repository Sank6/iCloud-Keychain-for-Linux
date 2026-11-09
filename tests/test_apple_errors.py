"""Typed, actionable Apple errors, 2FA retry, the sync failure flags and `icp logout`. No network."""
import argparse
import os
import plistlib
import tempfile
import unittest
from unittest import mock

import requests

from icp import net, ratelimit
from icp.auth import grandslam
from icp.auth.gsa import GSAClient, GSAError
from icp.auth.icloud import ICloudError
from icp.cli import app
from icp.transport.cloudkit import CloudKitError


class Resp:
    def __init__(self, content=b"", status=200):
        self.content, self.status_code, self.ok = content, status, 200 <= status < 300
        self.headers, self.url = {}, "https://gsa.apple.com/grandslam/GsService2"


class Dev:
    def meta_headers(self): return {}


class Anis:
    def headers(self): return {"X-Apple-I-MD": "a", "X-Apple-I-MD-M": "b"}


class Env(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for p in (mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": tmp.name}),
                  mock.patch.object(net, "MIN_GAP", 0)):
            p.start()
            self.addCleanup(p.stop)
        os.environ.pop("DBUS_SESSION_BUS_ADDRESS", None)   # never the real keyring (restored by patch)


class GsaErrorTests(Env):
    def test_first_request_403_non_plist_is_actionable(self):
        with mock.patch.object(requests, "post", return_value=Resp(b"x" * 146, 403)):
            with self.assertRaises(GSAError) as cm:
                GSAClient(Dev(), Anis())._request({"o": "init"})
        e = cm.exception
        self.assertEqual(e.kind, "blocked")
        msg = str(e)
        self.assertIn("HTTP 403", msg)
        self.assertIn("before looking at any password", msg)
        self.assertIn("icp doctor", msg)
        self.assertNotIn("non-plist", msg)

    def test_other_non_plist_keeps_old_text(self):
        with mock.patch.object(requests, "post", return_value=Resp(b"<html>", 404)):
            with self.assertRaises(GSAError) as cm:
                GSAClient(Dev(), Anis())._request({"o": "init"})
        self.assertIn("non-plist reply (6 bytes)", str(cm.exception))

    def test_offline_is_network_kind_not_auth(self):
        with mock.patch.object(requests, "post", side_effect=requests.ConnectionError("x")):
            with self.assertRaises(GSAError) as cm:
                GSAClient(Dev(), Anis())._request({"o": "init"})
        self.assertEqual(cm.exception.kind, "network")
        flags = app._failure_flags(cm.exception)
        self.assertTrue(flags["transient"])
        self.assertFalse(flags["auth"])        # being offline must not demand a sign-in

    def test_wrong_password_status_is_credentials_kind(self):
        from icp.auth import gsa
        self.assertEqual(gsa._status_kind({"Status": {"ec": -22406}}), "credentials")
        self.assertEqual(gsa._status_kind({"Status": {"ec": 5}}), "")


class FailureFlagTests(unittest.TestCase):
    def test_flags(self):
        blocked = ICloudError("x", kind="blocked")
        self.assertTrue(app._failure_flags(blocked)["auth"])
        self.assertTrue(app._failure_flags(GSAError("bad", kind="credentials"))["auth"])
        self.assertTrue(app._failure_flags(CloudKitError("x", kind="circuit"))["transient"])
        self.assertFalse(app._failure_flags(ICloudError("5xx", retry_after=60))["auth"])
        self.assertEqual(app._failure_flags(ICloudError("5xx", retry_after=60))["retry_after"], 60)


class TwoFactorRetryTests(unittest.TestCase):
    class FakeGsa:
        def __init__(self, reject):
            self.reject, self.submitted, self.triggered, self.auths = reject, [], 0, 0

        def authenticate(self, user, pw, stage):
            self.auths += 1
            st = {"au": "trustedDeviceSecondaryAuth"} if self.auths == 1 else {}
            return {"Status": st}, {"adsid": "1", "GsIdmsToken": "t"}

        def trigger_trusted_factor(self, *a): self.triggered += 1

        def submit_trusted_factor(self, code, *a):
            self.submitted.append(code)
            if len(self.submitted) <= self.reject:
                raise GSAError("trusted-device 2FA code rejected", kind="code")

    def run_auth(self, reject):
        codes = iter(["1", "2", "3", "4"])
        g, notes = self.FakeGsa(reject), []
        try:
            grandslam.authenticate(g, "u", "p", lambda kind: next(codes), notify=notes.append)
            err = None
        except GSAError as e:
            err = e
        return g, notes, err

    def test_mistyped_code_is_asked_again_without_a_new_push(self):
        g, notes, err = self.run_auth(reject=1)
        self.assertIsNone(err)
        self.assertEqual(g.submitted, ["1", "2"])
        self.assertEqual(g.triggered, 1)
        self.assertEqual(len(notes), 1)

    def test_gives_up_after_three_codes(self):
        g, _, err = self.run_auth(reject=5)
        self.assertEqual(err.kind, "code")
        self.assertEqual(len(g.submitted), grandslam.CODE_ATTEMPTS)


class LogoutTests(Env):
    def test_logout_clears_state_and_keeps_vault_by_default(self):
        from icp import paths
        from icp.auth import session
        session.save({"username": "me@icloud.com", "password": "pw"})
        paths.vault_file().write_bytes(b"vault")
        args = argparse.Namespace(wipe_device=False, keep_mirror=True, purge_vault=False,
                                  reset_keys=False)
        self.assertEqual(app.cmd_logout(args), 0)
        self.assertFalse(paths.session_file().exists())
        self.assertTrue(paths.vault_file().exists())
        st = ratelimit.load()
        self.assertTrue(st["needs_login"])             # surfaces as "sign-in needed" everywhere
        args.purge_vault = True
        app.cmd_logout(args)
        self.assertFalse(paths.vault_file().exists())

    def test_reset_keys_moves_files_aside(self):
        from icp import paths
        from icp.auth import session
        session.save({"a": 1})
        app.cmd_logout(argparse.Namespace(wipe_device=False, keep_mirror=True, purge_vault=False,
                                          reset_keys=True))
        self.assertTrue(list(paths.config_dir().glob("session.enc.lost-*")))



class UnattendedTests(unittest.TestCase):
    def test_no_terminal_without_force_counts_as_background(self):
        ns = lambda **k: argparse.Namespace(**k)  # noqa: E731
        with mock.patch("sys.stdin") as stdin:
            stdin.isatty.return_value = False
            self.assertTrue(app._unattended(ns(background=False, force=False)))
            self.assertFalse(app._unattended(ns(background=False, force=True)))   # GUI "Sync now"
            stdin.isatty.return_value = True
            self.assertFalse(app._unattended(ns(background=False, force=False)))
            self.assertTrue(app._unattended(ns(background=True, force=False)))


if __name__ == "__main__":
    unittest.main()
