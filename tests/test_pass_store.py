import base64
import os
import tempfile
import unittest
from unittest import mock

import nacl.secret

from icp.auth import session


class PassStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_xdg = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_CONFIG_HOME"] = self.tmp.name

    def tearDown(self):
        if self.old_xdg is None:
            os.environ.pop("XDG_CONFIG_HOME", None)
        else:
            os.environ["XDG_CONFIG_HOME"] = self.old_xdg
        self.tmp.cleanup()

    @mock.patch("icp.auth.session._run_pass")
    def test_reads_base64_key_from_pass(self, run_pass):
        key = b"k" * nacl.secret.SecretBox.KEY_SIZE
        run_pass.return_value = mock.Mock(returncode=0,
                                          stdout=base64.b64encode(key).decode() + "\nmetadata\n",
                                          stderr="")
        self.assertEqual(session._master_key(), key)
        run_pass.assert_called_once_with(["show", "icloud-keychain-for-linux/master-key"])

    @mock.patch("icp.auth.session._store_key")
    @mock.patch("icp.auth.session._run_pass")
    def test_imports_legacy_key_file(self, run_pass, store_key):
        run_pass.return_value = mock.Mock(returncode=1, stdout="", stderr="missing")
        key = b"x" * nacl.secret.SecretBox.KEY_SIZE
        from icp import paths
        paths.fallback_key_file().write_bytes(key)
        self.assertEqual(session._master_key(), key)
        store_key.assert_called_once_with(key)

    @mock.patch("icp.auth.session._store_key")
    @mock.patch("icp.auth.session._run_pass")
    def test_generates_key_when_entry_missing(self, run_pass, store_key):
        run_pass.return_value = mock.Mock(returncode=1, stdout="", stderr="missing")
        key = session._master_key()
        self.assertEqual(len(key), nacl.secret.SecretBox.KEY_SIZE)
        store_key.assert_called_once_with(key)


if __name__ == "__main__":
    unittest.main()
