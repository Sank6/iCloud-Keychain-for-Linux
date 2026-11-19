import unittest

from icp import psl
from icp.vault import host


class PslTests(unittest.TestCase):
    def test_registrable(self):
        self.assertEqual(psl.registrable_domain("login.example.co.uk"), "example.co.uk")
        self.assertEqual(psl.registrable_domain("a.b.example.com"), "example.com")
        self.assertEqual(psl.registrable_domain("someone.github.io"), "someone.github.io")
        self.assertEqual(psl.registrable_domain("localhost"), "localhost")
        self.assertEqual(psl.registrable_domain("10.0.0.1"), "10.0.0.1")

    def test_public_suffix(self):
        for h in ("co.uk", "com", "github.io", "blogspot.com"):
            self.assertTrue(psl.is_public_suffix(h), h)
        self.assertFalse(psl.is_public_suffix("example.com"))

    def test_match_never_crosses_shared_suffix(self):
        self.assertFalse(host.domains_match("a.github.io", "github.io"))
        self.assertFalse(host.domains_match("evil.co.uk", "co.uk"))
        self.assertFalse(host.domains_match("10.0.0.1", "0.0.1"))
        self.assertTrue(host.domains_match("login.example.co.uk", "example.co.uk"))
        self.assertTrue(host.domains_match("www.example.com", "example.com"))


if __name__ == "__main__":
    unittest.main()


class RelatedTests(unittest.TestCase):
    def test_related_and_choice_order(self):
        import os, tempfile
        from unittest import mock
        from icp import related
        from icp.vault.host import Credential, CredentialStore
        self.assertTrue(related.related("www.youtube.com", "accounts.google.com"))
        self.assertFalse(related.related("google.com", "google.com"))
        self.assertFalse(related.related("example.com", "google.com"))
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": d}):
            store = CredentialStore([Credential(domain="google.com", username="a", password="1"),
                                     Credential(domain="youtube.com", username="b", password="2")])
            self.assertEqual({c.username for c in store.match("youtube.com")}, {"a", "b"})
            self.assertEqual(store.match("youtube.com")[0].username, "b")  # exact beats related
            from icp import choices
            choices.record("youtube.com", "a")
            self.assertEqual(store.match("youtube.com")[0].username, "a")  # remembered choice first
