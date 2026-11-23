"""Offline tests for the desktop app's Qt-free logic (sections, search, sync status).

Run: .venv/bin/python -m unittest tests.test_gui_model
"""

import os
import tempfile
import unittest

from icp.gui import model
from icp.hme.client import HmeAlias
from icp.vault.host import Credential

LOGIN = Credential("github.com", "alice", "pw", "GitHub", mdat=1.0)
CODED = Credential("example.com", "bob", "pw", "Example", totp="otpauth://totp/x?secret=JBSWY3DP")
SHARED = Credential("bank.test", "carol", "pw", "Bank", group="Family", notes="joint account")
WIFI = Credential("AirPort", "HomeNet", "pw", "HomeNet")
UNTITLED = Credential("", "", "pw")
CREDS = [LOGIN, CODED, SHARED, WIFI, UNTITLED]


def alias(address, label="", active=True, domain=""):
    return HmeAlias(anonymous_id="id", address=address, label=label, note="",
                    forward_to="me@example.com", is_active=active, domain=domain,
                    created_at=0)


class SectionTests(unittest.TestCase):
    def test_all_excludes_wifi(self):
        self.assertNotIn(WIFI, model.credentials_for(CREDS, "all"))
        self.assertEqual(len(model.credentials_for(CREDS, "all")), 4)

    def test_wifi_section_is_only_wifi(self):
        self.assertEqual(model.credentials_for(CREDS, "wifi"), [WIFI])

    def test_codes_and_shared(self):
        self.assertEqual(model.credentials_for(CREDS, "codes"), [CODED])
        self.assertEqual(model.credentials_for(CREDS, "shared"), [SHARED])

    def test_sorted_by_title(self):
        titles = [model.title(c) for c in model.credentials_for(CREDS, "all")]
        self.assertEqual(titles, sorted(titles, key=str.lower))

    def test_counts(self):
        counts = model.section_counts(CREDS, [alias("a@icloud.com")])
        self.assertEqual(counts, {"all": 4, "codes": 1, "shared": 1, "wifi": 1, "hme": 1})


class SearchTests(unittest.TestCase):
    def test_matches_any_field_case_insensitively(self):
        self.assertEqual(model.credentials_for(CREDS, "all", "GITHUB"), [LOGIN])
        self.assertEqual(model.credentials_for(CREDS, "all", "carol"), [SHARED])
        self.assertEqual(model.credentials_for(CREDS, "all", "family"), [SHARED])
        self.assertEqual(model.credentials_for(CREDS, "all", "joint"), [SHARED])

    def test_never_matches_password(self):
        self.assertEqual(model.credentials_for([Credential("x.com", "u", "s3cret")], "all",
                                               "s3cret"), [])

    def test_aliases_active_first(self):
        old = alias("old@icloud.com", "Old", active=False)
        new = alias("new@icloud.com", "Zed")
        self.assertEqual(model.aliases_for([old, new]), [new, old])
        self.assertEqual(model.aliases_for([old, new], "old@"), [old])


class LabelTests(unittest.TestCase):
    def test_title_fallbacks(self):
        self.assertEqual(model.title(LOGIN), "GitHub")
        self.assertEqual(model.title(Credential("site.com", "u", "p")), "site.com")
        self.assertEqual(model.title(UNTITLED), "(untitled)")

    def test_wifi_has_no_website(self):
        self.assertEqual(model.website(WIFI), "")
        self.assertEqual(model.subtitle(WIFI), "Wi-Fi network")
        self.assertEqual(model.website(LOGIN), "github.com")


class StatusTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._old = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_CONFIG_HOME"] = self._tmp.name

    def tearDown(self):
        if self._old is None:
            os.environ.pop("XDG_CONFIG_HOME", None)
        else:
            os.environ["XDG_CONFIG_HOME"] = self._old
        self._tmp.cleanup()

    def _sign_in(self):
        from icp import paths
        paths.session_file().write_bytes(b"x")

    def test_relative_time(self):
        self.assertEqual(model.relative_time(None), "never")
        self.assertEqual(model.relative_time(100, now=130), "just now")
        self.assertEqual(model.relative_time(0.5, now=600.5), "10 min ago")
        self.assertEqual(model.relative_time(1, now=1 + 7200), "2 h ago")
        self.assertEqual(model.relative_time(1, now=1 + 86400), "1 day ago")

    def test_not_signed_in(self):
        text, problem = model.sync_status({})
        self.assertTrue(problem)
        self.assertIn("icp login", text)

    def test_needs_login(self):
        self._sign_in()
        text, problem = model.sync_status({"needs_login": True})
        self.assertTrue(problem)
        self.assertIn("expired", text)

    def test_ok_and_failed(self):
        self._sign_in()
        self.assertEqual(model.sync_status({"last_success": 1000}, now=1030),
                         ("Synced just now", False))
        text, problem = model.sync_status(
            {"last_success": 1000, "failures": 2, "last_error": "sync failed: boom"}, now=1030)
        self.assertTrue(problem)
        self.assertIn("boom", text)


if __name__ == "__main__":
    unittest.main()
