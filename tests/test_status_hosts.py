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

    def test_failures_count_and_reset(self):
        with mock.patch.object(status, "notify") as n:
            for _ in range(status.NOTIFY_AFTER):
                status.record_failure("sign-in: init failed: ec=-80045")
            self.assertEqual(status.read()["failures"], status.NOTIFY_AFTER)
            self.assertEqual(n.call_count, 1)  # notified once, at the threshold
            status.record_success()
        self.assertEqual(status.read()["failures"], 0)
        self.assertEqual(status.read()["last_error"], "")

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
