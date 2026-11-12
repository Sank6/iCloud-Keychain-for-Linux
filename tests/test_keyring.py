"""Keyring access (icp.keyring), the saved Apple ID (icp.account), master-key safety and mirror
robustness - all against an in-memory fake Secret Service; the real one is never touched."""
import base64
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

from icp import account, keyring, mirror
from icp.auth import session
from icp.vault.host import Credential


class FakeItem:
    def __init__(self, coll, label, attrs, secret):
        self.coll, self.label, self.attrs, self.secret = coll, label, dict(attrs), secret

    def get_attributes(self): return self.attrs
    def get_label(self): return self.label
    def set_label(self, v): self.label = v
    def get_secret(self): return self.secret
    def set_secret(self, v): self.secret = v
    def delete(self): self.coll.items.remove(self)


class FakeColl:
    def __init__(self, label="login", locked=False, dismiss=False):
        self.label, self.locked, self.dismiss, self.items = label, locked, dismiss, []
        self.collection_path = f"/org/freedesktop/secrets/collection/{label}"

    def get_label(self): return self.label
    def is_locked(self): return self.locked

    def unlock(self):
        if not self.dismiss:
            self.locked = False
        return self.dismiss

    def search_items(self, attrs):
        return [i for i in self.items if all(i.attrs.get(k) == v for k, v in attrs.items())]

    def create_item(self, label, attrs, secret, replace=False):
        if replace:
            self.items = [i for i in self.items if i.attrs != attrs]
        self.items.append(FakeItem(self, label, attrs, secret))


def fake_ss(*colls, fail=None):
    def init():
        if fail:
            raise fail
        return object()
    return mock.patch.dict(sys.modules, {"secretstorage": types.SimpleNamespace(
        dbus_init=init, get_default_collection=lambda c: colls[0],
        get_all_collections=lambda c: list(colls))})


class KeyringTests(unittest.TestCase):
    def test_unavailable(self):
        with fake_ss(fail=OSError("no bus")), self.assertRaises(keyring.KeyringUnavailable):
            keyring.open_collection()

    def test_locked_background_never_prompts(self):
        c = FakeColl(locked=True)
        with fake_ss(c), self.assertRaises(keyring.KeyringLocked):
            keyring.open_collection(interactive=False)
        self.assertTrue(c.locked)

    def test_interactive_unlocks_and_dismissal_raises(self):
        with fake_ss(FakeColl(locked=True)):
            self.assertFalse(keyring.open_collection().is_locked())
        with fake_ss(FakeColl(locked=True, dismiss=True)), self.assertRaises(keyring.KeyringLocked):
            keyring.open_collection()

    def test_collection_selection_by_label_or_id(self):
        a, b = FakeColl("login"), FakeColl("Passwords")
        with fake_ss(a, b):
            self.assertIs(keyring.open_collection("Passwords"), b)
            self.assertIs(keyring.open_collection("login"), a)
            self.assertIs(keyring.open_collection(), a)
            with self.assertRaises(keyring.KeyringUnavailable):
                keyring.open_collection("nope")


class AccountTests(unittest.TestCase):
    def test_save_load_forget_with_attributes(self):
        c = FakeColl()
        c.items.append(FakeItem(c, "other", {"application": "firefox"}, b"x"))
        with fake_ss(c):
            account.save("me@icloud.com", "pw1")
            account.save("me@icloud.com", "pw1")          # unchanged: no duplicate
            (item,) = c.search_items(account.ATTRS)
            self.assertEqual(item.attrs["user"], "me@icloud.com")
            self.assertEqual(item.attrs["xdg:schema"], "org.gnome.keyring.NetworkPassword")
            self.assertEqual(account.load(), ("me@icloud.com", "pw1"))
            account.save("me@icloud.com", None)           # "don't remember the password"
            self.assertEqual(account.load(), ("me@icloud.com", None))
            account.save("you@icloud.com", "pw2")         # switching accounts leaves one item
            self.assertEqual(len(c.search_items(account.ATTRS)), 1)
            self.assertEqual(account.forget(), 1)
        self.assertEqual(len(c.items), 1)                 # foreign item untouched

    def test_load_never_raises_without_keyring(self):
        with fake_ss(fail=OSError("no bus")):
            self.assertEqual(account.load(), (None, None))


class SessionKeyringTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        p = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": tmp.name})
        p.start()
        self.addCleanup(p.stop)

    def test_password_moves_to_keyring_and_back(self):
        c = FakeColl()
        with fake_ss(c):
            session.save({"username": "me@icloud.com", "password": "hunter2", "dsid": "1"})
            raw = session.paths.session_file().read_bytes()
            import nacl.secret
            blob = nacl.secret.SecretBox(session._master_key()).decrypt(raw)
            self.assertNotIn(b"hunter2", blob)                    # not in the blob any more
            self.assertEqual(session.load()["password"], "hunter2")   # but load() hands it back
            session.clear()
        self.assertEqual(c.search_items(account.ATTRS), [])

    def test_password_stays_in_blob_without_keyring(self):
        with fake_ss(fail=OSError("no bus")):
            session.save({"username": "me@icloud.com", "password": "hunter2"})
            self.assertEqual(session.load()["password"], "hunter2")

    def test_missing_keyring_key_with_data_is_refused(self):
        with fake_ss(FakeColl()):
            session.save({"a": 1})
        with fake_ss(FakeColl("fresh")), self.assertRaises(session.KeyLost):
            session._master_key()                 # a different/empty keyring: do not mint a key

    def test_file_key_is_migrated_into_the_keyring(self):
        with fake_ss(fail=OSError("no bus")):
            session.save({"a": 1})                # written with the 0600 key file
        file_key = base64.b64decode(session.paths.fallback_key_file().read_bytes())
        c = FakeColl()
        with fake_ss(c):
            self.assertEqual(session._master_key(), file_key)    # same key, data stays readable
            self.assertEqual(session.load(), {"a": 1})
        self.assertEqual(len(c.search_items({"application": "icp", "type": "master-key"})), 1)
        self.assertFalse(session.paths.fallback_key_file().exists())   # plaintext copy removed


class MirrorRobustnessTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        p = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": tmp.name})
        p.start()
        self.addCleanup(p.stop)
        os.environ.pop("ICP_NO_MIRROR", None)

    creds = [Credential(domain="a.com", username="u", password="p")]

    def test_empty_vault_never_wipes_the_mirror(self):
        c = FakeColl()
        mirror.reconcile(c, self.creds)
        res = mirror.reconcile(c, [])
        self.assertTrue(res.skipped)
        self.assertEqual(len(c.items), 1)

    def test_locked_background_is_skipped_with_a_hint(self):
        with fake_ss(FakeColl(locked=True)):
            res = mirror.sync_to_keyring(self.creds, interactive=False)
        self.assertIn("locked", res.skipped)
        self.assertIn("icp mirror", res.skipped)

    def test_unavailable_and_dismissed_are_skips_not_crashes(self):
        with fake_ss(fail=OSError("no bus")):
            self.assertIn("unavailable", mirror.sync_to_keyring(self.creds, interactive=True).skipped)
        with fake_ss(FakeColl(locked=True, dismiss=True)):
            self.assertTrue(mirror.sync_to_keyring(self.creds, interactive=True).skipped)

    def test_unchanged_vault_skips_reconcile_unless_forced(self):
        c = FakeColl()
        with fake_ss(c):
            self.assertEqual(mirror.sync_to_keyring(self.creds, interactive=True).added, 1)
            auto = mirror.sync_to_keyring(self.creds, interactive=False, force=False)
            self.assertEqual(auto.skipped, "unchanged since the last mirror")
            c.items.clear()                                   # someone deleted it in Seahorse
            self.assertEqual(mirror.sync_to_keyring(self.creds, interactive=True).added, 1)

    def test_collection_from_config(self):
        a, b = FakeColl("login"), FakeColl("Passwords")
        with fake_ss(a, b), mock.patch.dict(os.environ, {"ICP_MIRROR_COLLECTION": "Passwords"}):
            mirror.sync_to_keyring(self.creds, interactive=True)
        self.assertEqual((len(a.items), len(b.items)), (0, 1))

    def test_remove_all_only_removes_ours(self):
        c = FakeColl()
        c.items.append(FakeItem(c, "other", {"application": "x"}, b"s"))
        mirror.reconcile(c, self.creds)
        with fake_ss(c):
            self.assertEqual(mirror.remove_all(), 1)
        self.assertEqual([i.label for i in c.items], ["other"])


if __name__ == "__main__":
    unittest.main()
