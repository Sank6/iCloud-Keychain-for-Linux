"""Offline tests for the encrypted session store's master-key handling (temp config dir).

Covers the key-file fallback path only - no Secret Service is touched.

Run: .venv/bin/python -m unittest tests.test_session
"""

import base64
import os
import tempfile
import unittest


class MasterKeyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._old_xdg = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_CONFIG_HOME"] = self._tmp.name
        # no Secret Service: force the 0600 key file fallback
        self._old_dbus = os.environ.pop("DBUS_SESSION_BUS_ADDRESS", None)

    def tearDown(self):
        if self._old_xdg is None:
            os.environ.pop("XDG_CONFIG_HOME", None)
        else:
            os.environ["XDG_CONFIG_HOME"] = self._old_xdg
        if self._old_dbus is not None:
            os.environ["DBUS_SESSION_BUS_ADDRESS"] = self._old_dbus
        self._tmp.cleanup()

    @staticmethod
    def _key_file():
        from icp import paths
        return paths.fallback_key_file()

    def test_save_then_load(self):
        from icp.auth import session
        self.assertIsNone(session.load())  # nothing stored yet
        session.save({"username": "alice@example.com", "token": "t"})
        self.assertEqual(session.load()["username"], "alice@example.com")
        f = self._key_file()
        self.assertEqual(len(base64.b64decode(f.read_bytes())), 32)
        self.assertEqual(f.stat().st_mode & 0o777, 0o600)

    def test_raw_32_byte_key_still_accepted(self):
        """Keys written by versions before the base64 change must keep working."""
        from icp.auth import session
        session.save({"a": 1})
        f = self._key_file()
        f.write_bytes(base64.b64decode(f.read_bytes()))  # downgrade to the legacy raw form
        self.assertEqual(session.load(), {"a": 1})

    def test_unusable_key_is_replaced(self):
        """A key the keyring mangled (wrong length) is regenerated, not fed to SecretBox."""
        from icp.auth import session
        f = self._key_file()
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(b"\x00short")
        session.save({"a": 1})  # used to raise ValueError: key must be exactly 32 bytes
        self.assertEqual(len(base64.b64decode(f.read_bytes())), 32)
        self.assertEqual(session.load(), {"a": 1})

    def test_key_change_raises_session_error(self):
        from icp.auth import session
        session.save({"a": 1})
        self._key_file().write_bytes(base64.b64encode(os.urandom(32)))
        with self.assertRaises(session.SessionError):
            session.load()

    def test_undecryptable_caches_are_kept(self):
        from icp.auth import session
        from icp.hme import store as hme
        from icp.hme.client import HmeAlias
        from icp.vault import store as vault
        from icp.vault.host import Credential, CredentialStore

        session.save({"a": 1})
        vault.save_vault(CredentialStore([Credential("example.com", "alice", "pw", "Example")]))
        hme.save_aliases([HmeAlias("id1", "x@icloud.com", "shop", "", "me@icloud.com",
                                   True, "icloud.com", 0.0)])
        self.assertEqual(len(hme.load_aliases()), 1)
        self.assertEqual(len(vault.load_vault()), 1)

        self._key_file().write_bytes(base64.b64encode(os.urandom(32)))
        with self.assertRaises(session.SessionError):
            vault.load_vault()
        self.assertTrue(self._key_file().parent.joinpath("vault.enc").exists())  # never deleted
        self.assertEqual(hme.load_aliases(), [])
        self.assertTrue(self._key_file().parent.joinpath("aliases.enc").exists())

    def test_missing_key_with_data_is_refused_not_regenerated(self):
        from icp.auth import session
        session.save({"a": 1})
        self._key_file().unlink()
        with self.assertRaises(session.KeyLost):
            session._master_key()
        self.assertFalse(self._key_file().exists())  # nothing minted

    def test_reset_keys_moves_data_aside(self):
        from icp.auth import session
        session.save({"a": 1})
        done = session.reset_keys()
        self.assertTrue(any("session.enc" in d for d in done))
        self.assertFalse(self._key_file().exists())
        self.assertTrue(list(self._key_file().parent.glob("session.enc.lost-*")))
        session.save({"b": 2})  # a clean start works
        self.assertEqual(session.load(), {"b": 2})


if __name__ == "__main__":
    unittest.main()
