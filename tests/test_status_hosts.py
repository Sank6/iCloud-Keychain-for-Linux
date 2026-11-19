"""Sync status bookkeeping and native-host manifest checks (offline)."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from icp import hosts, status
from icp.const import EXTENSION_ID


class StatusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        p = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self.tmp.name})
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(self.tmp.cleanup)

    def test_state_publishes_display_file(self):
        from icp import ratelimit
        st = {}
        ratelimit.record_failure(st, "sign-in: init failed: ec=-80045", auth=True)
        shown = status.read()
        self.assertEqual(shown["failures"], 1)
        self.assertTrue(shown["needs_login"])
        self.assertIn("icp login", shown["hint"])
        ratelimit.record_success(st)
        shown = status.read()
        self.assertEqual((shown["failures"], shown["last_error"], shown["needs_login"]),
                         (0, "", False))
        self.assertNotIn("circuit", shown)

    def test_notifies_once_at_threshold(self):
        with mock.patch.object(status, "notify") as n:
            status.maybe_notify({"failures": 1})
            status.maybe_notify({"failures": status.NOTIFY_AFTER})
            status.maybe_notify({"failures": status.NOTIFY_AFTER + 1})
            self.assertEqual(n.call_count, 1)
            status.maybe_notify({"failures": 1, "needs_login": True, "hint": "x"})
            self.assertEqual(n.call_count, 2)

    def test_hint(self):
        self.assertIn("icp login", status.explain("not signed in - run: icp login"))
        self.assertEqual(status.explain("something unknown"), "")


class HostManifestTests(unittest.TestCase):
    def test_inspect(self):
        with tempfile.TemporaryDirectory() as d:
            nmh = Path(d)
            self.assertEqual(hosts.inspect(nmh, "chromium"), ["host manifest missing"])
            launcher = nmh / "launch"
            launcher.write_text("#!/bin/sh\n")
            launcher.chmod(0o755)
            (nmh / "org.icp.native.json").write_text(
                json.dumps(hosts.chromium_manifest(launcher)))
            self.assertEqual(hosts.inspect(nmh, "chromium"), [])
            m = hosts.chromium_manifest(launcher, extra_ids=["x" * 32])
            self.assertIn(f"chrome-extension://{EXTENSION_ID}/", m["allowed_origins"])
            self.assertEqual(len(m["allowed_origins"]), 2)


if __name__ == "__main__":
    unittest.main()
