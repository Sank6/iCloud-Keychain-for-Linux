"""A dismissed keyring prompt must raise, never mint a fallback key (which would orphan the vault)."""
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

from icp.auth import session


class FakeColl:
    def __init__(self, locked, dismissed):
        self._locked, self._dismissed = locked, dismissed
    def is_locked(self): return self._locked
    def unlock(self): return self._dismissed
    def search_items(self, attrs): return []
    def create_item(self, *a, **k): pass


class KeyringLockTests(unittest.TestCase):
    def _fake_ss(self, coll):
        m = types.SimpleNamespace(dbus_init=lambda: object(), get_default_collection=lambda c: coll)
        return mock.patch.dict(sys.modules, {"secretstorage": m})

    def test_dismissed_prompt_raises_and_writes_no_key_file(self):
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": d}), \
                self._fake_ss(FakeColl(locked=True, dismissed=True)):
            with self.assertRaises(session.KeyringLocked):
                session._master_key()
            self.assertFalse(os.path.exists(os.path.join(d, "icp", "master.key")))

    def test_missing_service_still_falls_back_to_key_file(self):
        def boom():
            raise OSError("no bus")
        m = types.SimpleNamespace(dbus_init=boom)
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": d}), \
                mock.patch.dict(sys.modules, {"secretstorage": m}):
            self.assertEqual(len(session._master_key()), 32)


if __name__ == "__main__":
    unittest.main()
