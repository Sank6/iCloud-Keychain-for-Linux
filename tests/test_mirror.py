"""Secret Service mirror: reconcile logic against an in-memory fake collection."""
import unittest

from icp import mirror
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
    def __init__(self): self.items = []
    def search_items(self, attrs):
        return [i for i in self.items if all(i.attrs.get(k) == v for k, v in attrs.items())]
    def create_item(self, label, attrs, secret, replace=False):
        self.items.append(FakeItem(self, label, attrs, secret))


def cred(domain, user, pw, **kw):
    return Credential(domain=domain, username=user, password=pw, **kw)


class ReconcileTests(unittest.TestCase):
    def test_add_update_remove(self):
        c = FakeColl()
        foreign = FakeItem(c, "other", {"application": "something-else"}, b"x")
        c.items.append(foreign)
        r = mirror.reconcile(c, [cred("a.com", "u", "p1"), cred("b.com", "v", "p2")])
        self.assertEqual((r.added, r.updated, r.removed), (2, 0, 0))
        r = mirror.reconcile(c, [cred("a.com", "u", "NEW")])  # b.com removed, a.com changed
        self.assertEqual((r.added, r.updated, r.removed), (0, 1, 1))
        self.assertIn(foreign, c.items)  # never touches items it doesn't own
        r = mirror.reconcile(c, [cred("a.com", "u", "NEW")])
        self.assertEqual((r.added, r.updated, r.removed), (0, 0, 0))  # idempotent

    def test_attributes_and_secret(self):
        c = FakeColl()
        mirror.reconcile(c, [cred("Example.com", "me", "pw", title="Example", totp="otpauth://x",
                                  notes="n")])
        (item,) = c.items
        self.assertEqual(item.attrs["server"], "example.com")
        self.assertEqual(item.attrs["user"], "me")
        self.assertEqual(item.attrs["xdg:schema"], "org.gnome.keyring.NetworkPassword")
        self.assertEqual(item.secret, b"pw")
        self.assertEqual(item.label, "Example (me)")
        self.assertNotIn("otpauth", repr(item.attrs) + repr(item.label))  # seeds/notes not mirrored

    def test_skips_empty_and_dedupes(self):
        c = FakeColl()
        mirror.reconcile(c, [cred("a.com", "u", ""), cred("", "u", "p"),
                             cred("a.com", "u", "old", mdat=1.0), cred("a.com", "u", "new", mdat=2.0)])
        self.assertEqual([i.secret for i in c.items], [b"new"])


if __name__ == "__main__":
    unittest.main()
