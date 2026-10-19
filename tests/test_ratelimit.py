"""Sync pacing (icp/ratelimit.py) and the no-2FA-push guard for unattended runs. No network."""

import os
import tempfile
import unittest
from unittest import mock

from icp import ratelimit
from icp.auth import grandslam


class PacingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        p = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self.tmp.name})
        p.start()
        self.addCleanup(p.stop)

    def test_minimum_interval_after_attempt(self):
        st = {}
        ratelimit.record_attempt(st, now=1000)
        self.assertFalse(ratelimit.may_sync(st, force=False, background=True, now=1100)[0])
        self.assertTrue(ratelimit.may_sync(st, force=False, background=True,
                                           now=1000 + ratelimit.MIN_INTERVAL)[0])
        self.assertTrue(ratelimit.may_sync(st, force=True, background=True, now=1100)[0])

    def test_backoff_doubles_and_is_capped(self):
        st = {}
        delays = []
        for _ in range(12):
            ratelimit.record_failure(st, "x", now=0)
            delays.append(st["next_allowed"])
        self.assertEqual(delays[:3], [300, 600, 1200])
        self.assertEqual(delays[-1], ratelimit.BACKOFF_MAX)

    def test_retry_after_wins_when_longer(self):
        st = {}
        ratelimit.record_failure(st, "429", retry_after=3600, now=0)
        self.assertEqual(st["next_allowed"], 3600)

    def test_login_block_stops_background_even_forced(self):
        st = {}
        ratelimit.record_failure(st, "auth", auth=True, now=0)
        self.assertFalse(ratelimit.may_sync(st, force=True, background=True, now=10**9)[0])
        self.assertTrue(ratelimit.may_sync(st, force=False, background=False, now=10**9)[0])
        ratelimit.clear_login_block()
        self.assertFalse(ratelimit.load().get("needs_login"))

    def test_success_resets(self):
        st = {"failures": 4, "needs_login": True}
        ratelimit.record_success(st, now=50)
        self.assertEqual((st["failures"], st["needs_login"]), (0, False))
        self.assertEqual(ratelimit.load()["last_success"], 50)

    def test_state_file_is_private(self):
        ratelimit.save({"a": 1})
        self.assertEqual(os.stat(ratelimit._file()).st_mode & 0o777, 0o600)


class NoPushInBackgroundTests(unittest.TestCase):
    def test_unattended_run_never_triggers_a_2fa_push(self):
        gsa = mock.Mock()
        gsa.authenticate.return_value = ({"Status": {"au": "trustedDeviceSecondaryAuth"}},
                                         {"adsid": "d", "GsIdmsToken": "t"})
        with self.assertRaises(grandslam.TwoFactorUnavailable):
            grandslam.authenticate(gsa, "u", "p", lambda k: "000000", interactive=False)
        gsa.trigger_trusted_factor.assert_not_called()
        gsa.trigger_sms_factor.assert_not_called()


if __name__ == "__main__":
    unittest.main()
